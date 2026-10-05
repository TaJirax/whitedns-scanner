package main

import (
	"encoding/csv"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"reachability-scanner/engine"
)

// Result tabs. "tunnel" overlaps the others: it lists DNS resolvers that are
// ready to carry a DNS tunnel.
const (
	TabAll      = "all"
	TabOK       = "ok"
	TabDead     = "dead"
	TabPoisoned = "poisoned"
	TabTunnel   = "tunnel"
)

// Row is one result as the UI shows it.
type Row struct {
	Seq          int    `json:"seq"`
	Label        string `json:"label"`
	URL          string `json:"url"`
	IP           string `json:"ip"`
	Answer       string `json:"answer"`
	Port         int    `json:"port"`
	Status       int    `json:"status"`
	LatencyMs    int    `json:"latencyMs"`
	Error        string `json:"error"`
	Protocol     string `json:"protocol"`
	Poisoned     bool   `json:"poisoned"`
	HdrDump      string `json:"hdrDump"`
	RA           bool   `json:"ra"`
	TC           bool   `json:"tc"`
	Rcode        int    `json:"rcode"`
	Edns         bool   `json:"edns"`
	TunnelReady  bool   `json:"tunnelReady"`
	TunnelReason string `json:"tunnelReason"`
	Category     string `json:"category"` // ok | dead | poisoned
}

func newRow(seq int, r *engine.ScanResult) Row {
	cat := TabOK
	switch {
	case r.IsPoisoned:
		cat = TabPoisoned
	case r.Error != "":
		cat = TabDead
	}
	return Row{
		Seq: seq, Label: r.Label, URL: r.URL, IP: r.ResolvedIP, Answer: r.DnsAnswer,
		Port: r.Port, Status: r.Status, LatencyMs: r.LatencyMs, Error: r.Error,
		Protocol: r.DnsProtocol, Poisoned: r.IsPoisoned, HdrDump: r.HdrDump,
		RA: r.RA, TC: r.TC, Rcode: r.Rcode, Edns: r.Edns,
		TunnelReady: r.TunnelReady, TunnelReason: r.TunnelReason, Category: cat,
	}
}

// Query selects a page of results.
type Query struct {
	Tab      string `json:"tab"`
	Search   string `json:"search"`
	Protocol string `json:"protocol"` // "" = any; else UDP, TCP, DoT, DoH
	SortBy   string `json:"sortBy"`   // seq | latency | target | port | status
	Desc     bool   `json:"desc"`
	Offset   int    `json:"offset"`
	Limit    int    `json:"limit"`
}

type Page struct {
	Rows   []Row          `json:"rows"`
	Total  int            `json:"total"`  // rows matching the query
	Counts map[string]int `json:"counts"` // per tab, ignoring search/protocol
}

// store keeps every result of the current scan. Results arrive from engine
// workers; the UI pages through them, so a million rows never cross into the
// webview at once.
type store struct {
	mu     sync.RWMutex
	rows   []Row
	counts map[string]int
}

func newStore() *store { return &store{counts: map[string]int{}} }

func (s *store) reset() {
	s.mu.Lock()
	s.rows = nil
	s.counts = map[string]int{}
	s.mu.Unlock()
}

func (s *store) add(r *engine.ScanResult) Row {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := newRow(len(s.rows)+1, r)
	s.rows = append(s.rows, row)
	s.counts[TabAll]++
	s.counts[row.Category]++
	if row.TunnelReady {
		s.counts[TabTunnel]++
	}
	return row
}

func (s *store) snapshotCounts() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]int, len(s.counts))
	for k, v := range s.counts {
		out[k] = v
	}
	return out
}

func (q Query) matches(r *Row) bool {
	switch q.Tab {
	case TabOK, TabDead, TabPoisoned:
		if r.Category != q.Tab {
			return false
		}
	case TabTunnel:
		if !r.TunnelReady {
			return false
		}
	}
	if q.Protocol != "" && !strings.HasPrefix(r.Protocol, q.Protocol) {
		return false
	}
	if q.Search != "" {
		needle := strings.ToLower(q.Search)
		hay := strings.ToLower(r.Label + " " + r.URL + " " + r.IP + " " + r.Answer + " " + r.Error + " " + r.Protocol + " " + strconv.Itoa(r.Port))
		if !strings.Contains(hay, needle) {
			return false
		}
	}
	return true
}

func (s *store) filter(q Query) []Row {
	s.mu.RLock()
	out := make([]Row, 0, min(len(s.rows), 4096))
	for i := range s.rows {
		if q.matches(&s.rows[i]) {
			out = append(out, s.rows[i])
		}
	}
	s.mu.RUnlock()

	less := func(a, b *Row) bool { return a.Seq < b.Seq }
	switch q.SortBy {
	case "latency":
		// Failed probes have no meaningful latency; keep them last.
		less = func(a, b *Row) bool {
			if (a.Error == "") != (b.Error == "") {
				return a.Error == ""
			}
			return a.LatencyMs < b.LatencyMs
		}
	case "target":
		less = func(a, b *Row) bool { return a.Label < b.Label }
	case "port":
		less = func(a, b *Row) bool { return a.Port < b.Port }
	case "status":
		less = func(a, b *Row) bool { return a.Status < b.Status }
	}
	sort.SliceStable(out, func(i, j int) bool {
		if q.Desc {
			return less(&out[j], &out[i])
		}
		return less(&out[i], &out[j])
	})
	return out
}

func (s *store) query(q Query) Page {
	all := s.filter(q)
	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	start := min(max(q.Offset, 0), len(all))
	end := min(start+limit, len(all))
	return Page{Rows: all[start:end], Total: len(all), Counts: s.snapshotCounts()}
}

func (s *store) exportCSV(q Query, path string, dns bool) (int, error) {
	rows := s.filter(q)
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if dns {
		_ = w.Write([]string{"resolver", "protocol", "port", "answer", "latency_ms", "poisoned", "recursion", "edns", "rcode", "tunnel_ready", "tunnel_reason", "error"})
		for _, r := range rows {
			_ = w.Write([]string{r.Label, r.Protocol, strconv.Itoa(r.Port), r.Answer, strconv.Itoa(r.LatencyMs),
				strconv.FormatBool(r.Poisoned), strconv.FormatBool(r.RA), strconv.FormatBool(r.Edns), strconv.Itoa(r.Rcode),
				strconv.FormatBool(r.TunnelReady), r.TunnelReason, r.Error})
		}
	} else {
		_ = w.Write([]string{"target", "url", "ip", "port", "status", "latency_ms", "error"})
		for _, r := range rows {
			_ = w.Write([]string{r.Label, r.URL, r.IP, strconv.Itoa(r.Port), strconv.Itoa(r.Status), strconv.Itoa(r.LatencyMs), r.Error})
		}
	}
	w.Flush()
	return len(rows), w.Error()
}
