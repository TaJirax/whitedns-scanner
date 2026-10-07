package engine

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Protocol fixtures return actual DNS wire packets over loopback sockets.
// No public resolver or external truth provider is used by these tests.
type dnsFixture struct {
	udp  *net.UDPConn
	tcp  net.Listener
	port int
}

func dnsAnswer(query []byte, ip string, bare bool) []byte {
	var request dnsmessage.Message
	if err := request.Unpack(query); err != nil || len(request.Questions) != 1 {
		return nil
	}
	question := request.Questions[0]
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.Header.ID, Response: true, RecursionDesired: true, RecursionAvailable: true}, Questions: request.Questions}
	header := dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 60}
	if question.Type == dnsmessage.TypeTXT {
		response.Answers = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.TXTResource{TXT: []string{"hello", "world"}}}}
	} else {
		address := net.ParseIP(ip).To4()
		var bytes [4]byte
		copy(bytes[:], address)
		response.Answers = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.AResource{A: bytes}}}
	}
	if !bare {
		response.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 4096}, Body: &dnsmessage.OPTResource{}}}
	}
	packet, _ := response.Pack()
	return packet
}

func newDNSFixture(t *testing.T, tlsMode bool, respond func([]byte) [][]byte) *dnsFixture {
	t.Helper()
	// UDP and TCP must share a port number; another program may hold the TCP
	// side of a random UDP port, so try a few.
	var udp *net.UDPConn
	var tcp net.Listener
	var port int
	for attempt := 0; tcp == nil; attempt++ {
		var err error
		if udp, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
			t.Fatal(err)
		}
		port = udp.LocalAddr().(*net.UDPAddr).Port
		if tcp, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port))); err != nil {
			udp.Close()
			if attempt == 20 {
				t.Fatal(err)
			}
		}
	}
	if tlsMode {
		cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		tcp = tls.NewListener(tcp, &tls.Config{Certificates: cert.TLS.Certificates})
		cert.Close()
	}
	var mu sync.Mutex
	var connections []net.Conn
	t.Cleanup(func() {
		udp.Close()
		tcp.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range connections {
			conn.Close()
		}
	})
	go func() {
		for {
			buffer := make([]byte, 4096)
			n, peer, err := udp.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			for _, packet := range respond(buffer[:n]) {
				_, _ = udp.WriteToUDP(packet, peer)
			}
		}
	}()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, conn)
			mu.Unlock()
			go func() {
				defer conn.Close()
				var length [2]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(length[:]))
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				for _, packet := range respond(query) {
					binary.BigEndian.PutUint16(length[:], uint16(len(packet)))
					_, _ = conn.Write(append(length[:], packet...))
				}
				if respond == nil {
					return
				}
			}()
		}
	}()
	return &dnsFixture{udp: udp, tcp: tcp, port: port}
}

func fixtureTruth() *TruthTable {
	truth := NewTruthTable("example.test")
	truth.TruthIPs["8.8.8.8"] = true
	// Offline: any other answer IP serves a certificate that is not example.test's.
	truth.checkCert = func(string) certVerdictKind { return certInvalid }
	return truth
}

func TestDNSAndTXTWireProtocols(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp", "dot"} {
		t.Run(protocol, func(t *testing.T) {
			server := newDNSFixture(t, protocol == "dot", func(query []byte) [][]byte { return [][]byte{dnsAnswer(query, "8.8.8.8", false)} })
			var answer, txt DnsProbeResult
			switch protocol {
			case "udp":
				answer = DnsProbeUDPWithDialer(context.Background(), "127.0.0.1", "example.test", fixtureTruth(), time.Second, nil, server.port)
				txt = DnsProbeTXTUDPWithDialer(context.Background(), "127.0.0.1", "nonce.example.test", time.Second, nil, server.port)
			case "tcp":
				answer = DnsProbeTCPWithDialer(context.Background(), "127.0.0.1", "example.test", fixtureTruth(), time.Second, nil, server.port)
				txt = DnsProbeTXTTCPWithDialer(context.Background(), "127.0.0.1", "nonce.example.test", time.Second, nil, server.port)
			case "dot":
				answer = DnsProbeDoTWithDialer(context.Background(), "127.0.0.1", "example.test", fixtureTruth(), time.Second, nil, server.port)
				txt = DnsProbeTXTDoTWithDialer(context.Background(), "127.0.0.1", "nonce.example.test", time.Second, nil, server.port)
			}
			if !answer.Responded || answer.IsPoisoned || len(answer.AnswerIPs) != 1 || answer.AnswerIPs[0] != "8.8.8.8" || !answer.Header.RA || !answer.EDNS {
				t.Fatalf("A probe: %+v", answer)
			}
			if !txt.Responded || len(txt.AnswerTXT) != 1 || txt.AnswerTXT[0] != "helloworld" || !txt.EDNS {
				t.Fatalf("TXT probe: %+v", txt)
			}
		})
	}
}

func TestUDPRejectsWrongTransactionAndFallsBackWithoutEDNS(t *testing.T) {
	for _, variant := range []string{"wrong-id", "bare-fallback", "edns-dropped", "poisoned", "malformed"} {
		t.Run(variant, func(t *testing.T) {
			server := newDNSFixture(t, false, func(query []byte) [][]byte {
				if variant == "malformed" {
					return [][]byte{{0, 1, 2}}
				}
				if variant == "poisoned" {
					return [][]byte{dnsAnswer(query, "1.1.1.1", false)}
				}
				if variant == "edns-dropped" && binary.BigEndian.Uint16(query[10:12]) > 0 {
					return nil // a middlebox silently eats EDNS queries
				}
				if variant == "bare-fallback" && binary.BigEndian.Uint16(query[10:12]) > 0 {
					packet := append([]byte(nil), query...)
					binary.BigEndian.PutUint16(packet[2:4], 0x8181)
					return [][]byte{packet}
				}
				packet := dnsAnswer(query, "8.8.8.8", variant == "bare-fallback" || variant == "edns-dropped")
				if variant == "wrong-id" {
					bad := dnsAnswer(query, "1.1.1.1", false)
					binary.BigEndian.PutUint16(bad[:2], binary.BigEndian.Uint16(query[:2])+1)
					return [][]byte{bad, packet}
				}
				return [][]byte{packet}
			})
			result := DnsProbeUDPWithDialer(context.Background(), "127.0.0.1", "example.test", fixtureTruth(), time.Second, nil, server.port)
			if variant == "malformed" {
				if result.Responded || result.Error == "" {
					t.Fatalf("malformed packet accepted: %+v", result)
				}
				return
			}
			if !result.Responded || result.IsPoisoned != (variant == "poisoned") {
				t.Fatalf("classification: %+v", result)
			}
			if (variant == "bare-fallback" || variant == "edns-dropped") && result.EDNS {
				t.Fatal("bare fallback was marked EDNS-capable")
			}
			if variant == "wrong-id" && result.AnswerIPs[0] != "8.8.8.8" {
				t.Fatal("wrong transaction ID was accepted")
			}
		})
	}
}

func TestDNSAndTXTCancelBlockedConnections(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp", "dot", "txt-udp", "txt-tcp", "txt-dot"} {
		t.Run(protocol, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			server := newDNSFixture(t, strings.HasSuffix(protocol, "dot"), func([]byte) [][]byte {
				select {
				case entered <- struct{}{}:
				default:
				}
				time.Sleep(3 * time.Second)
				return nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan DnsProbeResult, 1)
			go func() {
				switch protocol {
				case "udp":
					done <- DnsProbeUDPWithDialer(ctx, "127.0.0.1", "example.test", fixtureTruth(), 20*time.Second, nil, server.port)
				case "tcp":
					done <- DnsProbeTCPWithDialer(ctx, "127.0.0.1", "example.test", fixtureTruth(), 20*time.Second, nil, server.port)
				case "dot":
					done <- DnsProbeDoTWithDialer(ctx, "127.0.0.1", "example.test", fixtureTruth(), 20*time.Second, nil, server.port)
				case "txt-udp":
					done <- DnsProbeTXTUDPWithDialer(ctx, "127.0.0.1", "nonce.example.test", 20*time.Second, nil, server.port)
				case "txt-tcp":
					done <- DnsProbeTXTTCPWithDialer(ctx, "127.0.0.1", "nonce.example.test", 20*time.Second, nil, server.port)
				case "txt-dot":
					done <- DnsProbeTXTDoTWithDialer(ctx, "127.0.0.1", "nonce.example.test", 20*time.Second, nil, server.port)
				}
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("probe did not reach fixture")
			}
			cancel()
			select {
			case result := <-done:
				if result.Responded {
					t.Fatal("canceled probe succeeded")
				}
			case <-time.After(700 * time.Millisecond):
				t.Fatal("cancellation waited for the 20-second socket timeout")
			}
		})
	}
}

func useLocalTruthProvider(t *testing.T) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"Status":0,"RA":true,"Answer":[{"type":1,"data":"8.8.8.8"}]}`)
	}))
	old := trustedProviders
	trustedProviders = []trustedDoHProvider{{Name: "fixture", URL: server.URL + "?name=%s"}}
	t.Cleanup(func() { trustedProviders = old; server.Close() })
}

func TestExplicitResolverPortHasAccurateProgress(t *testing.T) {
	useLocalTruthProvider(t)
	for _, txt := range []bool{false, true} {
		t.Run(fmt.Sprint("txt=", txt), func(t *testing.T) {
			server := newDNSFixture(t, false, func(q []byte) [][]byte { return [][]byte{dnsAnswer(q, "8.8.8.8", false)} })
			cfg := DefaultConfig()
			cfg.OutputDir = t.TempDir()
			cfg.InputFile = filepath.Join(cfg.OutputDir, "targets.txt")
			cfg.DnsDiscoveryMode = !txt
			cfg.DnsTxtMode = txt
			cfg.DnsTxtDomain = "example.test"
			cfg.AutoConcurrency = false
			cfg.MaxConcurrent = 1
			cfg.StreamingAuto = false
			cfg.TimeoutSecs = 1
			if err := os.WriteFile(cfg.InputFile, []byte(fmt.Sprintf("127.0.0.1:%d\n", server.port)), 0600); err != nil {
				t.Fatal(err)
			}
			handler := &sniResultHandler{}
			scanner := NewEngine(cfg, handler)
			scanner.Start()
			if len(handler.rows) != 2 || scanner.totalCount != 2 {
				t.Fatalf("completed %d probes but progress total is %d", len(handler.rows), scanner.totalCount)
			}
		})
	}
}

func TestLargeTXTRepliesOverTCPAndTLS(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprint("tls=", encrypted), func(t *testing.T) {
			server := newDNSFixture(t, encrypted, func(query []byte) [][]byte {
				var request dnsmessage.Message
				if request.Unpack(query) != nil {
					return nil
				}
				text := make([]string, 32)
				for i := range text {
					text[i] = strings.Repeat("x", 255)
				}
				response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.Header.ID, Response: true, RecursionAvailable: true}, Questions: request.Questions, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: request.Questions[0].Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}, Body: &dnsmessage.TXTResource{TXT: text}}}}
				packet, _ := response.Pack()
				return [][]byte{packet}
			})
			var result DnsProbeResult
			if encrypted {
				result = DnsProbeTXTDoTWithDialer(context.Background(), "127.0.0.1", "nonce.example.test", time.Second, nil, server.port)
			} else {
				result = DnsProbeTXTTCPWithDialer(context.Background(), "127.0.0.1", "nonce.example.test", time.Second, nil, server.port)
			}
			if !result.Responded || len(result.AnswerTXT) != 1 || len(result.AnswerTXT[0]) != 32*255 {
				t.Fatalf("valid large TXT answer rejected: %+v", result)
			}
		})
	}
}

func TestResolverBatchCompletesAllResultsInMemoryAndStreaming(t *testing.T) {
	useLocalTruthProvider(t)
	var input strings.Builder
	for i := 0; i < 48; i++ {
		server := newDNSFixture(t, false, func(q []byte) [][]byte { return [][]byte{dnsAnswer(q, "8.8.8.8", false)} })
		fmt.Fprintf(&input, "127.0.0.1:%d\n", server.port)
	}
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint("streaming=", streaming), func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.OutputDir = t.TempDir()
			cfg.InputFile = filepath.Join(cfg.OutputDir, "targets.txt")
			cfg.DnsDiscoveryMode = true
			cfg.AutoConcurrency = false
			cfg.MaxConcurrent = 8
			cfg.StreamingAuto = false
			cfg.Streaming = streaming
			cfg.CountTotal = true
			cfg.TimeoutSecs = 1
			if err := os.WriteFile(cfg.InputFile, []byte(input.String()), 0600); err != nil {
				t.Fatal(err)
			}
			handler := &sniResultHandler{}
			scanner := NewEngine(cfg, handler)
			scanner.Start()
			if len(handler.rows) != 96 || scanner.totalCount != 96 {
				t.Fatalf("batch lost results: done=%d total=%d", len(handler.rows), scanner.totalCount)
			}
			for _, row := range handler.rows {
				if row.Error != "" {
					t.Fatalf("local resolver failed: %+v", row)
				}
			}
		})
	}
}
