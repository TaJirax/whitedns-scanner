package engine

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A clean resolver's answer for a CDN domain rarely matches the trusted
// provider's IPs exactly; it must be judged by the IP itself, not flagged.
func TestVerifyJudgesAnswersByEvidence(t *testing.T) {
	verdicts := map[string]certVerdictKind{"142.250.154.138": certValid, "203.0.113.9": certInvalid, "198.51.100.7": certUnknown}
	checked := map[string]int{}
	truth := NewTruthTable("google.com")
	truth.TruthIPs["142.251.20.100"] = true
	truth.checkCert = func(ip string) certVerdictKind { checked[ip]++; return verdicts[ip] }
	for _, c := range []struct {
		ips   []string
		clean bool
		why   string
	}{
		{[]string{"142.251.20.100"}, true, "in the truth table"},
		{[]string{"142.250.154.138"}, true, "another region's Google IP with a valid certificate"},
		{[]string{"10.10.34.35"}, false, "a private block-page address"},
		{[]string{"142.250.154.138", "10.10.34.36"}, false, "any private address is a lie"},
		{[]string{"203.0.113.9"}, false, "TLS completes with a certificate that is not google.com's"},
		{[]string{"198.51.100.7"}, true, "unreachable: no evidence of poisoning"},
		{[]string{"203.0.113.9", "142.250.154.138"}, true, "one provably genuine IP"},
		{[]string{"142.250.154.138"}, true, "cached"},
	} {
		if got := truth.Verify(c.ips); got != c.clean {
			t.Fatalf("%v (%s): clean=%v, want %v", c.ips, c.why, got, c.clean)
		}
	}
	if checked["142.250.154.138"] != 1 {
		t.Fatalf("certificate checks are not cached per IP: %v", checked)
	}
}

func TestVerifyDomainCertReadsTheCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	roots := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	addr := srv.Listener.Addr().String()
	if v := verifyDomainCert("example.com", addr, roots); v != certValid { // httptest's cert names example.com
		t.Fatalf("valid certificate: %v", v)
	}
	if v := verifyDomainCert("google.com", addr, roots); v != certInvalid {
		t.Fatalf("certificate for another name: %v", v)
	}
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := closed.Addr().String()
	closed.Close()
	if v := verifyDomainCert("google.com", dead, roots); v != certUnknown {
		t.Fatalf("unreachable IP: %v", v)
	}
}
