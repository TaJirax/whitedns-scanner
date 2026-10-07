package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

func (c *ScanConfig) ValidateAntiDPI() error {
	if c.AntiDPI && (c.DPIFragmentSize < 1 || c.DPIFragmentSize > 1024 || c.DPIFragmentDelayMs < 0 || c.DPIFragmentDelayMs > 20) {
		return fmt.Errorf("Anti-DPI needs 1–1024 bytes per fragment and 0–20 ms delay")
	}
	return nil
}
func (c *ScanConfig) antiDPIEnabled() bool {
	return c != nil && c.AntiDPI && !c.SNIScan && !c.DnsDiscoveryMode && !c.DnsTxtMode
}

// fragmentConn changes TCP write boundaries only. TLS bytes, the hostname,
// certificate policy and application payload stay intact. The OS may coalesce
// writes; this is a best-effort option, not a guarantee of DPI circumvention.
type fragmentConn struct {
	net.Conn
	mu         sync.Mutex
	ctx        context.Context
	size       int
	delay      time.Duration
	fragmented bool
}

func (c *fragmentConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fragmented || len(p) < 6 || p[0] != 22 || p[1] != 3 || p[5] != 1 {
		return c.Conn.Write(p)
	}
	c.fragmented = true
	written := 0
	for len(p) > 0 {
		if err := c.ctx.Err(); err != nil {
			return written, err
		}
		n := min(c.size, len(p))
		count, err := c.Conn.Write(p[:n])
		written += count
		if err != nil {
			return written, err
		}
		if count != n {
			return written, io.ErrShortWrite
		}
		p = p[n:]
		if len(p) > 0 && c.delay > 0 {
			timer := time.NewTimer(c.delay)
			select {
			case <-timer.C:
			case <-c.ctx.Done():
				timer.Stop()
				return written, c.ctx.Err()
			}
		}
	}
	return written, nil
}
func wrapAntiDPI(ctx context.Context, conn net.Conn, cfg *ScanConfig) net.Conn {
	if !cfg.antiDPIEnabled() {
		return conn
	}
	size := cfg.DPIFragmentSize
	if size < 1 {
		size = 64
	}
	return &fragmentConn{Conn: conn, ctx: ctx, size: size, delay: time.Duration(cfg.DPIFragmentDelayMs) * time.Millisecond}
}
func antiDPIDial(dial func(context.Context, string, string) (net.Conn, error), cfg *ScanConfig) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return wrapAntiDPI(ctx, conn, cfg), nil
	}
}
