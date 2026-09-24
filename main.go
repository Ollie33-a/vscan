package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// --- Data Structures ---

type PortResult struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
}

type WebResult struct {
	URL             string            `json:"url"`
	StatusCode      int               `json:"status_code"`
	ServerHeader    string            `json:"server_header,omitempty"`
	SecurityHeaders map[string]string `json:"security_headers,omitempty"`
}

type VulnResult struct {
	CPE      string `json:"cpe,omitempty"`
	CVE      string `json:"cve,omitempty"`
	Severity string `json:"severity,omitempty"`
}

type ScanReport struct {
	Target      string       `json:"target"`
	Timestamp   string       `json:"timestamp"`
	Duration    string       `json:"duration"`
	PortResults []PortResult `json:"port_results,omitempty"`
	WebResults  []WebResult  `json:"web_results,omitempty"`
	VulnResults []VulnResult `json:"vuln_results,omitempty"`
	Stats       ScanStats    `json:"stats"`
}

type ScanStats struct {
	TotalPorts  int `json:"total_ports"`
	OpenPorts   int `json:"open_ports"`
	ClosedPorts int `json:"closed_ports"`
	Filtered    int `json:"filtered_ports"`
}

// --- Scanner Engine ---

type Scanner struct {
	target  string
	startP  int
	endP    int
	timeout time.Duration
	rate    int
	workers int
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewScanner(target string, start, end int, timeout time.Duration, rate, workers int) *Scanner {
	ctx, cancel := context.WithCancel(context.Background())
	return &Scanner{
		target:  target,
		startP:  start,
		endP:    end,
		timeout: timeout,
		rate:    rate,
		workers: workers,
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (s *Scanner) Stop() {
	s.cancel()
}

// scanTCP performs a standard TCP connect scan with rate limiting
func (s *Scanner) scanTCP(ports <-chan int, results chan<- PortResult, wg *sync.WaitGroup, limiter <-chan time.Time) {
	defer wg.Done()

	for port := range ports {
		select {
		case <-s.ctx.Done():
			return
		case <-limiter:
			address := fmt.Sprintf("%s:%d", s.target, port)
			conn, err := net.DialTimeout("tcp", address, s.timeout)
			
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					results <- PortResult{Port: port, State: "filtered"}
				} else {
					results <- PortResult{Port: port, State: "closed"}
				}
				continue
			}
			conn.Close()
			results <- PortResult{Port: port, State: "open"}
		}
	}
}

// Run orchestrates the TCP scan
func (s *Scanner) RunTCP() ([]PortResult, ScanStats) {
	ports := make(chan int, s.workers)
	results := make(chan PortResult, 1000)
	var wg sync.WaitGroup

	// Rate limiter: ticks at the specified rate per second
	limiter := time.Tick(time.Second / time.Duration(s.rate))

	// Start workers
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go s.scanTCP(ports, results, &wg, limiter)
	}

	// Feed ports
	go func() {
		for p := s.startP; p <= s.endP; p++ {
			select {
			case <-s.ctx.Done():
				break
			case ports <- p:
			}
		}
		close(ports)
	}()

	// Close results channel when workers finish
	go func() {
		wg.Wait()
		close(results)
	}()

	var portResults []PortResult
	stats := ScanStats{TotalPorts: (s.endP - s.startP) + 1}

	for res := range results {
		portResults = append(portResults, res)
		switch res.State {
		case "open":
			stats.OpenPorts++
		case "closed":
			stats.ClosedPorts++
		case "filtered":
			stats.Filtered++
		}
	}

	return portResults, stats
}

// --- Web & Vulnerability Scanning Concepts ---

func ScanWeb(targetURL string) (*WebResult, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	webRes := &WebResult{
		URL:             targetURL,
		StatusCode:      resp.StatusCode,
		ServerHeader:    resp.Header.Get("Server"),
		SecurityHeaders: make(map[string]string),
	}

	headersToCheck := []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"}
	for _, h := range headersToCheck {
		if val := resp.Header.Get(h); val != "" {
			webRes.SecurityHeaders[h] = val
		} else {
			webRes.SecurityHeaders[h] = "MISSING"
		}
	}
	return webRes, nil
}

func MapVulnerabilities(serverHeader string) []VulnResult {
	// Conceptual mapping. In production, this would query the NVD API using a generated CPE.
	var vulns []VulnResult
	if strings.Contains(strings.ToLower(serverHeader), "apache/2.4.41") {
		vulns = append(vulns, VulnResult{
			CPE:      "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
			CVE:      "CVE-2022-22720",
			Severity: "CRITICAL",
		})
	}
	return vulns
}

// --- Main Execution ---

func main() {
	target := flag.String("target", "127.0.0.1", "Target IP or Hostname")
	startPort := flag.Int("start", 1, "Start port")
	endPort := flag.Int("end", 100, "End port")
	timeout := flag.Duration("timeout", 500*time.Millisecond, "Scan timeout per port")
	rate := flag.Int("rate", 100, "Packets per second limit")
	workers := flag.Int("workers", 20, "Number of concurrent workers")
	jsonOut := flag.Bool("json", false, "Output results as JSON")
	webTarget := flag.String("web", "", "Target URL for web scanning (e.g., http://example.com)")

	flag.Parse()

	fmt.Println("VecScan by Vectalith Labs")
	fmt.Printf("Initializing scan for %s (%d-%d) at %d pps...\n", *target, *startPort, *endPort, *rate)

	scanner := NewScanner(*target, *startPort, *endPort, *timeout, *rate, *workers)

	// Graceful Shutdown Handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n[!] Interrupt received. Shutting down gracefully...")
		scanner.Stop()
	}()

	startTime := time.Now()
	report := ScanReport{
		Target:    *target,
		Timestamp: startTime.Format(time.RFC3339),
	}

	// Run Port Scan
	report.PortResults, report.Stats = scanner.RunTCP()

	// Run Web Scan if requested
	if *webTarget != "" {
		webRes, err := ScanWeb(*webTarget)
		if err == nil {
			report.WebResults = append(report.WebResults, *webRes)
			report.VulnResults = append(report.VulnResults, MapVulnerabilities(webRes.ServerHeader)...)
		} else {
			log.Printf("Web scan failed for %s: %v", *webTarget, err)
		}
	}

	report.Duration = time.Since(startTime).String()

	// Output Results
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report)
	} else {
		fmt.Printf("\nScan Complete for %s in %s\n", *target, report.Duration)
		fmt.Printf("Open: %d | Closed: %d | Filtered: %d\n", report.Stats.OpenPorts, report.Stats.ClosedPorts, report.Stats.Filtered)
		
		if len(report.WebResults) > 0 {
			fmt.Println("\n--- Web Scan Results ---")
			for _, w := range report.WebResults {
				fmt.Printf("URL: %s | Status: %d | Server: %s\n", w.URL, w.StatusCode, w.ServerHeader)
			}
		}
		
		if len(report.VulnResults) > 0 {
			fmt.Println("\n--- Potential Vulnerabilities ---")
			for _, v := range report.VulnResults {
				fmt.Printf("%s (%s) - %s\n", v.CVE, v.Severity, v.CPE)
			}
		}
	}
}