package engine

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestOriginalNineServiceDomainsAreUnchanged(t *testing.T) {
	want := []string{"workers.dev", "pages.dev", "gemini.google.com", "notebooklm.google.com", "instagram.com", "chatgpt.com", "web.telegram.org", "reddit.com", "claude.ai"}
	if !reflect.DeepEqual(DefaultProbeDomains(), want) {
		t.Fatal("original service set changed")
	}
	cf, _ := FindEdgeProvider("cloudflare")
	if !reflect.DeepEqual(cf.ProbeDomains, want) {
		t.Fatalf("Cloudflare changed: %v", cf.ProbeDomains)
	}
	for _, id := range []string{"render", "fly", "railway", "vercel", "netlify", "koyeb", "glitch", "fastly", "akamai"} {
		provider, ok := FindEdgeProvider(id)
		if !ok {
			t.Fatal(id)
		}
		for _, common := range want[2:] {
			found := false
			for _, d := range provider.ProbeDomains {
				if d == common {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s lost %s", id, common)
			}
		}
		for _, foreign := range want[:2] {
			for _, d := range provider.ProbeDomains {
				if d == foreign {
					t.Fatalf("%s kept Cloudflare-only %s", id, d)
				}
			}
		}
		for _, domain := range provider.PlatformDomains {
			found := false
			for _, d := range provider.ProbeDomains {
				if d == domain {
					found = true
				}
			}
			if !found {
				t.Fatal("platform equivalent missing")
			}
		}
	}
}

func TestServiceChecksActuallyProbeAllNineThroughCandidate(t *testing.T) {
	seen := map[string]int{}
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Host]++
		mu.Unlock()
		_, _ = w.Write([]byte("<html><body>" + r.Host + "</body></html>"))
	}))
	defer server.Close()
	cfg := DefaultConfig()
	cfg.InputFile = filepath.Join(t.TempDir(), "targets.txt")
	cfg.OutputDir = t.TempDir()
	cfg.ProbeDomains = DefaultProbeDomains()
	cfg.AutoConcurrency = false
	cfg.MaxConcurrent = 2
	cfg.StreamingAuto = false
	cfg.RetryCount = 0
	if err := os.WriteFile(cfg.InputFile, []byte(server.URL+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	handler := &sniResultHandler{}
	NewEngine(cfg, handler).Start()
	if len(handler.rows) != 1 || handler.rows[0].Error != "" || handler.rows[0].ServicePassed != 9 || handler.rows[0].ServiceTotal != 9 {
		t.Fatalf("service results: %+v", handler.rows)
	}
	for _, domain := range DefaultProbeDomains() {
		if seen[domain] != 1 {
			t.Fatalf("%s got %d requests", domain, seen[domain])
		}
	}
}

func TestCommonServiceSuccessCannotCreditWrongPlatform(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "chatgpt.com" {
			_, _ = w.Write([]byte("<html>chatgpt.com</html>"))
		} else {
			w.WriteHeader(503)
		}
	}))
	defer server.Close()
	cfg := DefaultConfig()
	cfg.InputFile = filepath.Join(t.TempDir(), "targets.txt")
	cfg.OutputDir = t.TempDir()
	cfg.ProbeDomains = []string{"vercel.app", "chatgpt.com"}
	cfg.RequiredProbeDomains = []string{"vercel.app"}
	cfg.AutoConcurrency = false
	cfg.MaxConcurrent = 1
	cfg.StreamingAuto = false
	cfg.RetryCount = 0
	if err := os.WriteFile(cfg.InputFile, []byte(server.URL+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	handler := &sniResultHandler{}
	NewEngine(cfg, handler).Start()
	if len(handler.rows) != 1 || !strings.Contains(handler.rows[0].Error, "no fronting domain") || handler.rows[0].ServicePassed != 1 {
		t.Fatalf("wrong platform credited: %+v", handler.rows)
	}
}
