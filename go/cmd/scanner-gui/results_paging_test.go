package main

import (
	"reflect"
	"testing"
)

func pagingFixture(size int) *store {
	s := newStore()
	categories := []string{TabOK, TabDead, TabPoisoned}
	for i := 0; i < size; i++ {
		s.addRow(Row{Label: "resolver", Protocol: []string{"UDP/53", "TCP/53", "DoH"}[i%3],
			Category: categories[i%3], Hijacked: i%5 == 0, TunnelReady: i%7 == 0})
	}
	return s
}

// Compare the optimized page path to the existing full filter/sort semantics,
// including overlay tabs, reverse order, filters and out-of-range pages.
func TestScanOrderPagingMatchesFullQuery(t *testing.T) {
	s := pagingFixture(137)
	for _, sortBy := range []string{"", "seq"} {
		for _, tab := range []string{"", TabAll, TabOK, TabDead, TabPoisoned, TabHijacked, TabTunnel, "unknown"} {
			for _, search := range []string{"", "RESOLVER", "missing"} {
				for _, protocol := range []string{"", "UDP", "DoH"} {
					for _, desc := range []bool{false, true} {
						for _, offset := range []int{-1, 0, 50, 137, 200} {
							for _, limit := range []int{0, 17, 1000, 1001} {
								q := Query{SortBy: sortBy, Tab: tab, Search: search, Protocol: protocol, Desc: desc, Offset: offset, Limit: limit}
								filtered := s.filter(q)
								n := limit
								if n <= 0 || n > 1000 {
									n = 100
								}
								start := min(max(offset, 0), len(filtered))
								end := min(start+n, len(filtered))
								got := s.query(q)
								if got.Total != len(filtered) || !reflect.DeepEqual(got.Rows, filtered[start:end]) || !reflect.DeepEqual(got.Counts, s.snapshotCounts()) {
									t.Fatalf("query %+v differs from full filtering: %+v", q, got)
								}
							}
						}
					}
				}
			}
		}
	}
	page := s.query(Query{})
	page.Counts[TabAll] = 0
	page.Rows[0].Label = "modified"
	if s.snapshotCounts()[TabAll] != 137 || s.query(Query{}).Rows[0].Label != "resolver" {
		t.Fatal("query results must be independent snapshots")
	}
}

func BenchmarkLiveResultPage(b *testing.B) {
	s := pagingFixture(50000)
	q := Query{Tab: TabAll, SortBy: "seq", Desc: true, Limit: 100}
	b.Run("paged", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = s.query(q)
		}
	})
	b.Run("full-filter-reference", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = s.filter(q)
		}
	})
}
