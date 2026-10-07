package engine

// asn.go — the ASN tables the WhiteDNS Android app ships (cleanip-finder's
// bundled filtered_ipv4.csv / filtered_ipv6.csv, byte for byte), so the desktop
// can pick the same networks and turn them into scan targets. Grouping, order,
// search and export follow the cleanip-finder terminal UI's ASN picker
// (internal/ui/tui.go loadASNFile, asnexport.ExportTargetsToTXT).

import (
	"embed"
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

//go:embed asndata/filtered_ipv4.csv asndata/filtered_ipv6.csv
var asnFS embed.FS

// ASNSummary is one network in the picker; the ranges stay on the Go side.
type ASNSummary struct {
	ASN     string `json:"asn"` // "AS58224"
	Name    string `json:"name"`
	Domain  string `json:"domain"`
	Type    string `json:"type"` // isp, hosting, business, …
	Country string `json:"country"`
	IPv4    int    `json:"ipv4"` // IPv4 ranges
	IPv6    int    `json:"ipv6"` // IPv6 ranges
}

type asnRecord struct {
	ASNSummary
	v4, v6 []string
}

var (
	asnOnce  sync.Once
	asnIndex map[string]*asnRecord
	asnOrder []*asnRecord // by ASN, as the TUI lists them
	asnErr   error
)

func loadASNs() error {
	asnOnce.Do(func() {
		asnIndex = map[string]*asnRecord{}
		for _, file := range []struct {
			path string
			v6   bool
		}{{"asndata/filtered_ipv4.csv", false}, {"asndata/filtered_ipv6.csv", true}} {
			if asnErr = readASNFile(file.path, file.v6); asnErr != nil {
				return
			}
		}
		for _, r := range asnIndex {
			sort.Strings(r.v4) // networks sorted within each ASN, as in the TUI
			sort.Strings(r.v6)
			asnOrder = append(asnOrder, r)
		}
		sort.Slice(asnOrder, func(i, j int) bool { return asnOrder[i].ASN < asnOrder[j].ASN })
	})
	return asnErr
}

var seen = map[string]bool{}

func readASNFile(path string, v6 bool) error {
	f, err := asnFS.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord, r.LazyQuotes = -1, true // a few rows carry stray quotes
	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("ASN table %s: %w", path, err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[h] = i
	}
	get := func(rec []string, name string) string {
		if i, ok := col[name]; ok && i < len(rec) {
			return strings.Trim(strings.TrimSpace(rec[i]), `"`)
		}
		return ""
	}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("ASN table %s: %w", path, err)
		}
		id, network := strings.ToUpper(get(rec, "asn")), get(rec, "network")
		if id == "" || network == "" {
			continue
		}
		a := asnIndex[id]
		if a == nil {
			a = &asnRecord{ASNSummary: ASNSummary{ASN: id, Name: get(rec, "as_name"), Domain: get(rec, "as_domain"), Type: get(rec, "type"), Country: get(rec, "country_code")}}
			asnIndex[id] = a
		}
		if seen[id+" "+network] { // the TUI keeps each network once per ASN
			continue
		}
		seen[id+" "+network] = true
		if v6 {
			a.v6 = append(a.v6, network)
			a.IPv6++
		} else {
			a.v4 = append(a.v4, network)
			a.IPv4++
		}
	}
}

// normalizeASN accepts "58224", "as58224" or "AS58224". Curated groups in the
// tables (IRHYBRID, IRTCP, IRUDP) are named, not numbered, and pass unchanged.
func normalizeASN(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s != "" && strings.Trim(s, "0123456789") == "" {
		s = "AS" + s
	}
	return s
}

func familyHas(a *asnRecord, family string) bool {
	switch family {
	case "ipv4":
		return a.IPv4 > 0
	case "ipv6":
		return a.IPv6 > 0
	}
	return true
}

// SearchASNs lists the ASNs of a dataset — "ipv4", "ipv6" or ""/"both", like
// the TUI's family screen — whose name or AS number contains query
// (case-insensitive; empty lists all), in ASN order.
func SearchASNs(query, family string) ([]ASNSummary, error) {
	if err := loadASNs(); err != nil {
		return nil, err
	}
	q := strings.ToLower(strings.TrimSpace(query))
	out := []ASNSummary{}
	for _, a := range asnOrder {
		if !familyHas(a, family) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(a.Name), q) && !strings.Contains(strings.ToLower(a.ASN), q) {
			continue
		}
		out = append(out, a.ASNSummary)
	}
	return out, nil
}

// ASNRanges returns the CIDRs of the given ASNs in family, IPv4 first.
func ASNRanges(ids []string, family string) ([]string, error) {
	if err := loadASNs(); err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, id := range ids {
		a := asnIndex[normalizeASN(id)]
		if a == nil {
			return nil, fmt.Errorf("unknown ASN %q", id)
		}
		var ranges []string
		if family != "ipv6" {
			ranges = append(ranges, a.v4...)
		}
		if family != "ipv4" {
			ranges = append(ranges, a.v6...)
		}
		for _, r := range ranges {
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the selected ASNs have no %s ranges", map[string]string{"ipv4": "IPv4", "ipv6": "IPv6"}[family])
	}
	return out, nil
}
