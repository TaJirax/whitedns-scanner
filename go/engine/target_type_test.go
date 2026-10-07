package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTargetKindDoesNotExpandRanges(t *testing.T) {
	for _, tc := range []struct{ line, kind string }{
		{"192.0.2.1", TargetIP}, {"192.0.2.1:8443", TargetIP}, {"https://192.0.2.1:443/path", TargetIP},
		{"0.0.0.0/0", TargetIP}, {"::/0", TargetIP}, {"[2001:db8::1]:8443", TargetIP}, {"label | 2001:db8::1", TargetIP},
		{"edge.example.com", TargetDomain}, {"edge.example.com:8443", TargetDomain}, {"label | https://edge.example.com/path", TargetDomain}, {"localhost", TargetDomain},
	} {
		got, err := TargetKind(tc.line)
		if err != nil || got != tc.kind {
			t.Fatalf("%q classified as %q, %v", tc.line, got, err)
		}
	}
	for _, bad := range []string{"999.1.1.1", "example.com:", "bad domain.example", "ftp://edge.example.com", "192.0.2.1/99"} {
		if _, err := TargetKind(bad); err == nil {
			t.Fatalf("accepted invalid target %q", bad)
		}
	}
}

func TestTargetFileSelectionValidatesWithoutExpandingCIDRs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("# ranges\n0.0.0.0/0\n::/0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTargetFile(path, TargetIP); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTargetFile(path, TargetDomain); err == nil {
		t.Fatal("IP ranges accepted in domain mode")
	}
	if err := os.WriteFile(path, []byte("edge.example.com\n192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTargetFile(path, TargetDomain); err == nil {
		t.Fatal("mixed list accepted in domain mode")
	}
}
