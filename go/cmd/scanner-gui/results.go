package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"reachability-scanner/engine"
)

// Result tabs. ok/dead/poisoned split the results; hijacked and tunnel are
// overlays (a DNS answer can be both clean and hijacked, as in the reports).
const (
	TabAll      = "all"
	TabOK       = "ok"
	TabDead     = "dead"
	TabPoisoned = "poisoned"
	TabHijacked = "hijacked"
	TabTunnel   = "tunnel"
)

// Row is one result as the UI shows it.
type Row struct {
	ServicePassed  int    `json:"servicePassed"`
	ServiceTotal   int    `json:"serviceTotal"`
	PassedDomains  string `json:"passedDomains"`
	ServiceSummary string `json:"serviceSummary"`
	Kind           string `json:"kind"`
	Seq            int    `json:"seq"`
	Label          string `json:"label"`
	URL            string `json:"url"`
	IP             string `json:"ip"`
	Answer         string `json:"answer"`
	Port           int    `json:"port"`
	Status         int    `json:"status"`
	LatencyMs      int    `json:"latencyMs"`
	Error          string `json:"error"`
	Protocol       string `json:"protocol"`
	Poisoned       bool   `json:"poisoned"`
	Hijacked       bool   `json:"hijacked"`
	HdrDump        string `json:"hdrDump"`
	RA             bool   `json:"ra"`
	TC             bool   `json:"tc"`
	Rcode          int    `json:"rcode"`
	Edns           bool   `json:"edns"`
	TunnelReady    bool   `json:"tunnelReady"`
	TunnelReason   string `json:"tunnelReason"`
	Category       string `json:"category"` // ok | dead | poisoned
}

func newRow(seq int, r *engine.ScanResult) Row {
	row := Row{
		ServicePassed: r.ServicePassed, ServiceTotal: r.ServiceTotal, PassedDomains: r.PassedDomains, ServiceSummary: r.ServiceSummary, Kind: r.Kind, Seq: seq, Label: r.Label, URL: r.URL, IP: r.ResolvedIP, Answer: r.DnsAnswer,
		Port: r.Port, Status: r.Status, LatencyMs: r.LatencyMs, Error: r.Error,
		Protocol: r.DnsProtocol, Poisoned: r.IsPoisoned, HdrDump: r.HdrDump,
		RA: r.RA, TC: r.TC, Rcode: r.Rcode, Edns: r.Edns,
		TunnelReady: r.TunnelReady, TunnelReason: r.TunnelReason,
		Hijacked: r.DnsProtocol != "" && r.ResolvedIP != "" && engine.IsHijackedIP(r.ResolvedIP),
	}
	row.Category = categorize(row)
	return row
}

func categorize(r Row) string {
	switch {
	case r.Poisoned:
		return TabPoisoned
	case r.Error != "":
		return TabDead
	}
	return TabOK
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

// store keeps every result of the scan being shown. The UI pages through it,
// so a million rows never cross into the webview at once.
type store struct {
	mu     sync.RWMutex
	rows   []Row
	counts map[string]int
	next   int // last Seq given out; deleting rows never reuses one
}

func newStore() *store { return &store{counts: map[string]int{}} }

func (s *store) reset() {
	s.mu.Lock()
	s.rows = nil
	s.counts = map[string]int{}
	s.next = 0
	s.mu.Unlock()
}

func (s *store) addRow(row Row) Row {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	row.Seq = s.next
	s.rows = append(s.rows, row)
	s.count(row, 1)
	return row
}

func (s *store) count(row Row, delta int) {
	s.counts[TabAll] += delta
	s.counts[row.Category] += delta
	if row.Hijacked {
		s.counts[TabHijacked] += delta
	}
	if row.TunnelReady {
		s.counts[TabTunnel] += delta
	}
}

// remove deletes every row match accepts, keeping the others in scan order,
// and returns how many it deleted.
func (s *store) remove(match func(*Row) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.rows[:0]
	for i := range s.rows {
		if match(&s.rows[i]) {
			s.count(s.rows[i], -1)
			continue
		}
		kept = append(kept, s.rows[i])
	}
	n := len(s.rows) - len(kept)
	clear(s.rows[len(kept):])
	s.rows = kept
	return n
}

func (s *store) add(r *engine.ScanResult) Row { return s.addRow(newRow(0, r)) }

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
	case TabHijacked:
		if !r.Hijacked {
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
		hay := strings.ToLower(r.Label + " " + r.URL + " " + r.IP + " " + r.Answer + " " + r.Error + " " + r.Protocol + " " + strconv.Itoa(r.Port))
		if !strings.Contains(hay, strings.ToLower(q.Search)) {
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
	if q.SortBy == "" || q.SortBy == "seq" {
		return s.queryScanOrder(q)
	}
	all := s.filter(q)
	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	start := min(max(q.Offset, 0), len(all))
	end := min(start+limit, len(all))
	return Page{Rows: all[start:end], Total: len(all), Counts: s.snapshotCounts()}
}

// queryScanOrder copies only the requested page for the default live view.
// Sorting and copying the entire store on every refresh can hold up result
// writers on large runs. Rows already have monotonically increasing Seq.
func (s *store) queryScanOrder(q Query) Page {
	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset := max(q.Offset, 0)
	s.mu.RLock()
	defer s.mu.RUnlock()
	counts := make(map[string]int, len(s.counts))
	for key, value := range s.counts {
		counts[key] = value
	}
	rows := make([]Row, 0, limit)
	filtered := q.Search != "" || q.Protocol != ""
	switch q.Tab {
	case TabOK, TabDead, TabPoisoned, TabHijacked, TabTunnel:
		filtered = true
	}
	if !filtered {
		total := len(s.rows)
		start := min(offset, total)
		end := start + min(limit, total-start)
		for i := start; i < end; i++ {
			index := i
			if q.Desc {
				index = total - 1 - i
			}
			rows = append(rows, s.rows[index])
		}
		return Page{Rows: rows, Total: total, Counts: counts}
	}
	total := 0
	for i := range s.rows {
		index := i
		if q.Desc {
			index = len(s.rows) - 1 - i
		}
		row := &s.rows[index]
		if !q.matches(row) {
			continue
		}
		if total >= offset && len(rows) < limit {
			rows = append(rows, *row)
		}
		total++
	}
	return Page{Rows: rows, Total: total, Counts: counts}
}

// ---- CSV ------------------------------------------------------------------

// csvColumns is the full results.csv written into every run folder; it keeps
// every field, so a past run reloads into the Results page exactly.
var csvColumns = []string{"target", "url", "ip", "answer", "port", "status", "latency_ms", "error", "protocol",
	"poisoned", "hijacked", "recursion", "truncated", "rcode", "edns", "tunnel_ready", "tunnel_reason", "header", "kind", "service_passed", "service_total", "passed_domains", "service_summary"}

func rowRecord(r Row) []string {
	b := strconv.FormatBool
	return []string{r.Label, r.URL, r.IP, r.Answer, strconv.Itoa(r.Port), strconv.Itoa(r.Status), strconv.Itoa(r.LatencyMs),
		r.Error, r.Protocol, b(r.Poisoned), b(r.Hijacked), b(r.RA), b(r.TC), strconv.Itoa(r.Rcode), b(r.Edns),
		b(r.TunnelReady), r.TunnelReason, r.HdrDump, r.Kind, strconv.Itoa(r.ServicePassed), strconv.Itoa(r.ServiceTotal), r.PassedDomains, r.ServiceSummary}
}

func writeRowsCSV(path string, rows []Row) (int, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write(csvColumns)
	for _, r := range rows {
		_ = w.Write(rowRecord(r))
	}
	w.Flush()
	return len(rows), w.Error()
}

func (s *store) exportCSV(q Query, path string) (int, error) {
	return writeRowsCSV(path, s.filter(q))
}

// loadCSV replaces the store's rows with a results.csv from a past run.
func (s *store) loadCSV(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("empty results file")
	}
	col := map[string]int{}
	for i, h := range header {
		col[h] = i
	}
	get := func(rec []string, name string) string {
		if i, ok := col[name]; ok && i < len(rec) {
			return rec[i]
		}
		return ""
	}
	atoi := func(v string) int { n, _ := strconv.Atoi(v); return n }
	isTrue := func(v string) bool { return v == "true" }

	s.reset()
	for {
		rec, err := r.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		row := Row{
			ServicePassed: atoi(get(rec, "service_passed")), ServiceTotal: atoi(get(rec, "service_total")), PassedDomains: get(rec, "passed_domains"), ServiceSummary: get(rec, "service_summary"), Kind: get(rec, "kind"), Label: get(rec, "target"), URL: get(rec, "url"), IP: get(rec, "ip"), Answer: get(rec, "answer"),
			Port: atoi(get(rec, "port")), Status: atoi(get(rec, "status")), LatencyMs: atoi(get(rec, "latency_ms")),
			Error: get(rec, "error"), Protocol: get(rec, "protocol"), Poisoned: isTrue(get(rec, "poisoned")),
			Hijacked: isTrue(get(rec, "hijacked")), RA: isTrue(get(rec, "recursion")), TC: isTrue(get(rec, "truncated")),
			Rcode: atoi(get(rec, "rcode")), Edns: isTrue(get(rec, "edns")), TunnelReady: isTrue(get(rec, "tunnel_ready")),
			TunnelReason: get(rec, "tunnel_reason"), HdrDump: get(rec, "header"),
		}
		row.Category = categorize(row)
		s.addRow(row)
	}
}

func (s *store) all() []Row { return s.filter(Query{}) }

// cleanIPs lists every passed HTTP endpoint as ip:port, fastest first and
// once each: the addresses to put in Worker / CDN configs for IP fronting.
func (s *store) cleanIPs() string {
	rows := s.filter(Query{Tab: TabOK})
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].LatencyMs < rows[j].LatencyMs })
	var b strings.Builder
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Protocol != "" || r.IP == "" { // DNS rows are resolvers, not fronting IPs
			continue
		}
		line := net.JoinHostPort(r.IP, strconv.Itoa(r.Port))
		if !seen[line] {
			seen[line] = true
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}
