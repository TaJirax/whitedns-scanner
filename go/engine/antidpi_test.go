package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type recordingConn struct {
	net.Conn
	writes [][]byte
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}
func TestAntiDPIChangesOnlyClientHelloWriteBoundaries(t *testing.T) {
	base := &recordingConn{}
	cfg := DefaultConfig()
	cfg.AntiDPI = true
	cfg.DPIFragmentSize = 3
	cfg.DPIFragmentDelayMs = 0
	c := wrapAntiDPI(context.Background(), base, cfg)
	connect := []byte("CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	c.Write(connect)
	hello := []byte{22, 3, 1, 0, 12, 1, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8}
	n, err := c.Write(hello)
	if err != nil || n != len(hello) {
		t.Fatal(n, err)
	}
	if len(base.writes) != 7 {
		t.Fatalf("ClientHello not split: %d", len(base.writes))
	}
	if !bytes.Equal(bytes.Join(base.writes[1:], nil), hello) {
		t.Fatal("TLS bytes changed")
	}
	c.Write(hello)
	if len(base.writes) != 8 {
		t.Fatal("later writes were fragmented")
	}
	for _, mode := range []string{"sni", "dns", "txt"} {
		cfg.SNIScan = mode == "sni"
		cfg.DnsDiscoveryMode = mode == "dns"
		cfg.DnsTxtMode = mode == "txt"
		if wrapAntiDPI(context.Background(), base, cfg) != base {
			t.Fatalf("leaked into %s", mode)
		}
	}
}
func TestAntiDPIRealTLSAndProxyKeepOriginalHostname(t *testing.T) {
	seen := make(chan string, 8)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	origin.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) { seen <- h.ServerName; return nil, nil }}
	origin.StartTLS()
	defer origin.Close()
	pool := x509.NewCertPool()
	pool.AddCert(origin.Certificate())
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	forwarder, _ := testHTTPForwarder(t)
	cfg := DefaultConfig()
	cfg.AntiDPI = true
	cfg.DPIFragmentSize = 31
	cfg.DPIFragmentDelayMs = 0
	for _, kind := range []string{"", "http-proxy"} {
		address := origin.Listener.Addr().String()
		rawURL := "https://example.com:" + port + "/"
		if kind != "" {
			address = forwarder.Listener.Addr().String()
			rawURL = origin.URL
		}
		targets, _ := parseBaseTargetsFromLine(address)
		transport, err := EndpointTransportWithDPI(targets[0], kind, "must-not-leak.example", time.Second, cfg)
		if err != nil {
			t.Fatal(err)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
		client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
		response, err := client.Get(rawURL)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		transport.CloseIdleConnections()
		name := <-seen
		if kind == "" && name != "example.com" {
			t.Fatalf("original SNI lost: %q", name)
		}
		if name == "must-not-leak.example" {
			t.Fatal("forged SNI leaked to IP/proxy")
		}
	}
}
