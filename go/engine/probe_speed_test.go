package engine

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// A resolver that accepts packets/connections but never answers must cost
// about one probe timeout, not one per protocol: UDP (2 attempts) and TCP run
// at the same time, so ~2 timeouts total instead of ~3 in sequence.
func TestDeadResolverProbesRunConcurrently(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	port := udp.LocalAddr().(*net.UDPAddr).Port
	tcp, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("TCP port %d taken: %v", port, err)
	}
	defer tcp.Close()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			defer c.Close() // hold open, never answer
		}
	}()

	const timeout = 300 * time.Millisecond
	start := time.Now()
	results := DnsProbe(context.Background(), "127.0.0.1", "example.com", NewTruthTable("example.com"),
		timeout, nil, nil, []int{port}, true)
	elapsed := time.Since(start)

	if len(results) != 2 || results[0].Protocol != "UDP/"+strconv.Itoa(port) || results[1].Protocol != "TCP/"+strconv.Itoa(port) {
		t.Fatalf("results out of order: %+v", results)
	}
	for _, r := range results {
		if r.Responded {
			t.Fatalf("%s responded from a silent resolver", r.Protocol)
		}
	}
	if elapsed > 2*timeout+250*time.Millisecond {
		t.Fatalf("dead resolver took %v; probes are not running concurrently", elapsed)
	}
}
