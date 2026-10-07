package engine

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func runServiceScan(t *testing.T, server *httptest.Server, limited bool, domains []string) []ScanResult {
	t.Helper()
	cfg := DefaultConfig()
	cfg.InputFile = filepath.Join(t.TempDir(), "targets.txt")
	cfg.OutputDir = t.TempDir()
	cfg.ProbeDomains = domains
	cfg.AutoConcurrency, cfg.MaxConcurrent, cfg.StreamingAuto = false, 9, false
	cfg.TimeoutSecs, cfg.RetryCount, cfg.LimitedNetwork = 1, 1, limited
	if err := os.WriteFile(cfg.InputFile, []byte(server.URL+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	handler := &sniResultHandler{}
	NewEngine(cfg, handler).Start()
	return handler.rows
}

// Limited network mode brings back the patient checks: a domain whose first
// answer is lost to a timeout gets its retry, and service checks run 3 at a time.
func TestLimitedNetworkRetriesTimeoutsAndPacesChecks(t *testing.T) {
	t.Run("a timed-out domain is retried", func(t *testing.T) {
		for _, limited := range []bool{true, false} {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					time.Sleep(1300 * time.Millisecond) // the first answer misses the 1 s timeout
				}
				_, _ = w.Write([]byte("<html>" + r.Host + "</html>"))
			}))
			rows := runServiceScan(t, server, limited, []string{"front.example"})
			server.Close()
			passed := len(rows) == 1 && rows[0].Error == "" && rows[0].PassedDomains == "front.example"
			if passed != limited || (calls.Load() == 2) != limited {
				t.Fatalf("limited=%v: passed=%v after %d requests: %+v", limited, passed, calls.Load(), rows)
			}
		}
	})
	t.Run("service checks run 3 at a time", func(t *testing.T) {
		for limited, want := range map[bool]int32{true: 3, false: 9} {
			var inFlight, peak atomic.Int32
			var mu sync.Mutex
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := inFlight.Add(1)
				mu.Lock()
				peak.Store(max(peak.Load(), n))
				mu.Unlock()
				time.Sleep(150 * time.Millisecond)
				inFlight.Add(-1)
				_, _ = w.Write([]byte("<html>" + r.Host + "</html>"))
			}))
			// One IP with room for every check, so only the per-IP pacing limits it.
			cfg := DefaultConfig()
			cfg.ProbeDomains, cfg.MaxConcurrent = DefaultProbeDomains(), 27
			cfg.TimeoutSecs, cfg.RetryCount, cfg.LimitedNetwork = 2, 0, limited
			eng := NewEngine(cfg, &sniResultHandler{})
			eng.state = "RUNNING"
			eng.initServiceClient()
			targets, _ := parseBaseTargetsFromLine(server.URL)
			jobs, results := make(chan Target, 1), make(chan ScanResult, 1)
			jobs <- targets[0]
			close(jobs)
			eng.wg.Add(1)
			eng.scanWorker(context.Background(), jobs, results)
			row := <-results
			server.Close()
			if row.ServicePassed != 9 || peak.Load() != want {
				t.Fatalf("limited=%v: %d checks at once (want %d): %+v", limited, peak.Load(), want, row)
			}
		}
	})
}

// A middlebox drops EDNS queries and the bare answer is slow: limited network
// gives the fallback its own full timeout, as before; normally both share one.
func TestLimitedNetworkGivesDNSFallbackItsOwnTimeout(t *testing.T) {
	defer limitedNetwork.Store(false)
	server := newDNSFixture(t, false, func(query []byte) [][]byte {
		if binary.BigEndian.Uint16(query[10:12]) > 0 {
			return nil // EDNS dropped
		}
		time.Sleep(700 * time.Millisecond)
		return [][]byte{dnsAnswer(query, "8.8.8.8", true)}
	})
	for _, limited := range []bool{false, true} {
		limitedNetwork.Store(limited)
		result := DnsProbeUDPWithDialer(context.Background(), "127.0.0.1", "example.test", fixtureTruth(), time.Second, nil, server.port)
		if result.Responded != limited {
			t.Fatalf("limited=%v: responded=%v (%s)", limited, result.Responded, result.Error)
		}
	}
}
