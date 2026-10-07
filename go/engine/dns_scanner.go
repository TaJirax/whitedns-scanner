package engine

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// ════════════════════════════════════════════════════════════════════════════════
// DNS DISCOVERY ENGINE — High-Precision Resolver Scanner
//
// Designed for hostile network environments with active DNS poisoning.
// Probes resolvers across 4 protocols and validates answer integrity
// against a "Truth Table" fetched from trusted DoH providers.
// ════════════════════════════════════════════════════════════════════════════════

// DnsProbeResult holds the outcome of a single DNS protocol probe against one resolver.
type DnsProbeResult struct {
	Protocol   string        // "UDP", "TCP", "DoT", "DoH"
	Responded  bool          // Did we get a parseable DNS response?
	IsPoisoned bool          // Did the answer IPs mismatch the truth table?
	AnswerIPs  []string      // A-record IPs extracted from the response
	AnswerTXT  []string      // TXT strings extracted from the response
	TTFB       time.Duration // Time to first byte of the DNS response
	Error      string        // Human-readable error, empty on success

	// Header holds the parsed DNS response header (all flags + section counts).
	// HeaderOK reports whether the header was successfully parsed.
	Header   DnsHeader
	HeaderOK bool
	// EDNS is true when the resolver echoed an EDNS0 OPT record, signalling it
	// accepts large UDP payloads — a prerequisite for high-bandwidth tunneling.
	EDNS bool
}

// DnsHeader is the fully-decoded 12-byte DNS message header (RFC 1035 §4.1.1).
// Exposed so callers can inspect every flag — not just the answer records —
// which is what the "full header dump" output and tunnel classifier rely on.
type DnsHeader struct {
	ID      uint16 // Transaction ID
	QR      bool   // Query (false) / Response (true)
	Opcode  uint8  // 0=QUERY, 1=IQUERY, 2=STATUS
	AA      bool   // Authoritative Answer
	TC      bool   // TrunCation — answer did not fit, retry over TCP
	RD      bool   // Recursion Desired (what we asked for)
	RA      bool   // Recursion Available — resolver is an open recursor
	Z       uint8  // Reserved (3 bits)
	Rcode   uint8  // Response code (0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN, 5=REFUSED)
	QDCount uint16 // Questions
	ANCount uint16 // Answer records
	NSCount uint16 // Authority records
	ARCount uint16 // Additional records
}

// parseDnsHeader decodes the fixed 12-byte header at the start of a DNS message.
func parseDnsHeader(packet []byte) (DnsHeader, error) {
	if len(packet) < 12 {
		return DnsHeader{}, fmt.Errorf("packet too short for header: %d bytes", len(packet))
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	return DnsHeader{
		ID:      binary.BigEndian.Uint16(packet[0:2]),
		QR:      flags&0x8000 != 0,
		Opcode:  uint8((flags >> 11) & 0x0F),
		AA:      flags&0x0400 != 0,
		TC:      flags&0x0200 != 0,
		RD:      flags&0x0100 != 0,
		RA:      flags&0x0080 != 0,
		Z:       uint8((flags >> 4) & 0x07),
		Rcode:   uint8(flags & 0x0F),
		QDCount: binary.BigEndian.Uint16(packet[4:6]),
		ANCount: binary.BigEndian.Uint16(packet[6:8]),
		NSCount: binary.BigEndian.Uint16(packet[8:10]),
		ARCount: binary.BigEndian.Uint16(packet[10:12]),
	}, nil
}

// String renders the header as a compact single-line dump for reports, e.g.
// "id=0x1a2b QR AA=0 TC=0 RD RA rcode=0 qd=1 an=2 ns=0 ar=1".
func (h DnsHeader) String() string {
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	return fmt.Sprintf("id=0x%04x qr=%d op=%d aa=%d tc=%d rd=%d ra=%d z=%d rcode=%d qd=%d an=%d ns=%d ar=%d",
		h.ID, b(h.QR), h.Opcode, b(h.AA), b(h.TC), b(h.RD), b(h.RA), h.Z, h.Rcode,
		h.QDCount, h.ANCount, h.NSCount, h.ARCount)
}

// ════════════════════════════════════════════════════════════════════════════════
// TRUTH TABLE — The "Ground Truth" for Integrity Verification
// ════════════════════════════════════════════════════════════════════════════════

// trustedDoHProvider defines a DoH endpoint for fetching the truth table.
type trustedDoHProvider struct {
	Name string
	URL  string // Full URL template; %s is replaced with the domain
}

// trustedProviders is the ordered fallback list of DoH providers.
// Cloudflare first, then Google, then Quad9.
var trustedProviders = []trustedDoHProvider{
	{Name: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query?name=%s&type=A"},
	{Name: "Google", URL: "https://dns.google/resolve?name=%s&type=A"},          // Google's JSON API is /resolve
	{Name: "Quad9", URL: "https://dns.quad9.net:5053/dns-query?name=%s&type=A"}, // Quad9 serves JSON on 5053
}

// dohJSONResponse models the JSON wire format returned by DoH providers
// when queried with Accept: application/dns-json.
type dohJSONResponse struct {
	Status int  `json:"Status"`
	TC     bool `json:"TC"` // Truncated
	RD     bool `json:"RD"` // Recursion Desired
	RA     bool `json:"RA"` // Recursion Available — open recursor
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// TruthTable holds the verified "correct" IPs for a target domain.
// Used to detect DNS poisoning: if a resolver returns IPs not in this set,
// the resolver is marked as POISONED.
type TruthTable struct {
	Domain   string
	TruthIPs map[string]bool // Set of known-correct A-record IPs
	mu       sync.RWMutex
	Provider string // Which DoH provider succeeded

	certs     sync.Map                        // answer IP -> *certCheck
	checkCert func(ip string) certVerdictKind // tests replace the TLS check
}

// NewTruthTable creates an empty truth table for a given domain.
func NewTruthTable(domain string) *TruthTable {
	return &TruthTable{
		Domain:   domain,
		TruthIPs: make(map[string]bool),
	}
}

// FetchTruth populates the truth table by querying trusted DoH providers.
// Tries each provider in order; stops on first success.
// Falls back to hardcoded well-known IPs if all providers fail.
func (t *TruthTable) FetchTruth() error {
	return t.FetchTruthContext(context.Background())
}

// FetchTruthContext allows Stop to interrupt trusted-provider setup as well as
// resolver probes. FetchTruth remains available to existing callers.
func (t *TruthTable) FetchTruthContext(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		},
	}
	defer client.CloseIdleConnections()

	for _, provider := range trustedProviders {
		if err := ctx.Err(); err != nil {
			return err
		}
		url := fmt.Sprintf(provider.URL, neturl.QueryEscape(t.Domain))

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/dns-json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			continue
		}

		var dohResp dohJSONResponse
		if err := json.Unmarshal(body, &dohResp); err != nil {
			continue
		}

		if dohResp.Status != 0 {
			continue
		}

		for _, ans := range dohResp.Answer {
			if ans.Type == 1 { // A record
				ip := strings.TrimSpace(ans.Data)
				if net.ParseIP(ip) != nil {
					t.TruthIPs[ip] = true
				}
			}
		}

		if len(t.TruthIPs) > 0 {
			t.Provider = provider.Name
			return nil
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// ── Hardcoded fallback for well-known domains ──
	// If all DoH providers are blocked (deep censorship), use known IPs
	// so the scanner can still detect obvious poisoning.
	fallbacks := map[string][]string{
		"google.com":    {"142.250.80.46", "142.250.80.78", "142.250.80.110"},
		"speedtest.net": {"151.139.72.2"},
		"facebook.com":  {"157.240.1.35", "157.240.3.35"},
	}

	if ips, ok := fallbacks[t.Domain]; ok {
		for _, ip := range ips {
			t.TruthIPs[ip] = true
		}
		t.Provider = "Hardcoded Fallback"
		return nil
	}

	return fmt.Errorf("truth table: all DoH providers failed and no hardcoded fallback for %q", t.Domain)
}

// Verify reports whether a resolver's answer is genuine (true) or poisoned.
//
// An exact match with the truth table is not enough to call an answer
// poisoned: CDN domains such as google.com answer with different IPs per
// region and per resolver, so a clean resolver usually returns IPs the
// trusted provider did not. An answer is therefore:
//   - clean when any IP is in the truth table;
//   - poisoned when any IP is private or reserved (block pages such as
//     10.10.34.35);
//   - otherwise judged by the IP itself: clean if it serves a certificate
//     valid for the domain, which only the real operator can, and poisoned if
//     it completes TLS with a certificate that is not. An IP that cannot be
//     reached proves nothing either way and is not called poisoned.
//
// Certificate checks are cached per IP, so each distinct answer is checked once.
func (t *TruthTable) Verify(ips []string) bool {
	t.mu.RLock()
	for _, ip := range ips {
		if t.TruthIPs[ip] {
			t.mu.RUnlock()
			return true
		}
	}
	t.mu.RUnlock()
	for _, ip := range ips {
		if isHijackedIP(ip) {
			return false
		}
	}
	if t.Domain == "" || len(ips) == 0 {
		return true
	}
	unproven := false
	for _, ip := range ips[:min(len(ips), 3)] {
		switch t.certVerdict(ip) {
		case certValid:
			return true
		case certUnknown:
			unproven = true
		}
	}
	return unproven
}

type certVerdictKind int

const (
	certUnknown certVerdictKind = iota // unreachable, or TLS failed before a certificate: no evidence
	certValid
	certInvalid
)

type certCheck struct {
	once    sync.Once
	verdict certVerdictKind
}

func (t *TruthTable) certVerdict(ip string) certVerdictKind {
	v, _ := t.certs.LoadOrStore(ip, &certCheck{})
	c := v.(*certCheck)
	c.once.Do(func() {
		if t.checkCert != nil {
			c.verdict = t.checkCert(ip)
		} else {
			c.verdict = verifyDomainCert(t.Domain, net.JoinHostPort(ip, "443"), nil)
		}
	})
	return c.verdict
}

// verifyDomainCert connects to address with the domain as SNI and verifies
// the certificate chain and name (roots nil = the system's).
func verifyDomainCert(domain, address string, roots *x509.CertPool) certVerdictKind {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &tls.Config{ServerName: domain, RootCAs: roots})
	if err == nil {
		conn.Close()
		return certValid
	}
	var bad *tls.CertificateVerificationError
	if errors.As(err, &bad) {
		return certInvalid
	}
	return certUnknown
}

// ════════════════════════════════════════════════════════════════════════════════
// DNS WIRE PROTOCOL — Manual Packet Construction (No External Dependencies)
// ════════════════════════════════════════════════════════════════════════════════

// ednsUDPPayloadSize is the advertised EDNS0 receive-buffer size. 4096 lets the
// resolver return large answers in a single UDP datagram — both a robustness win
// (fewer truncations) and the signal we use to gauge tunnel bandwidth.
const ednsUDPPayloadSize = 4096

var udpResponseBuffers = sync.Pool{New: func() any { return new([ednsUDPPayloadSize]byte) }}

// buildDnsQuery constructs a raw DNS query for the given domain and record type.
// Returns the wire-format bytes and the randomized transaction ID.
// Uses crypto/rand for TXID to evade pattern-based DPI blocking AND to let the
// caller validate that a response is genuinely ours (anti-spoofing). When edns
// is true an EDNS0 OPT record is added so we can detect large-payload support.
func buildDnsQuery(domain string, qtype uint16, edns bool) ([]byte, uint16) {
	// Generate cryptographically random transaction ID
	var txidBytes [2]byte
	_, _ = rand.Read(txidBytes[:])
	txid := binary.BigEndian.Uint16(txidBytes[:])

	arCount := byte(0x00)
	if edns {
		arCount = 0x01
	}

	// DNS Header (12 bytes)
	// Flags: 0x0100 = standard query, recursion desired (RD=1)
	header := []byte{
		txidBytes[0], txidBytes[1], // Transaction ID
		0x01, 0x00, // Flags: Standard query, RD=1
		0x00, 0x01, // QDCOUNT: 1 question
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, arCount, // ARCOUNT: 1 if EDNS OPT appended, else 0
	}

	// DNS Question section — encode domain as labels
	question := encodeDomainName(domain)

	// QTYPE, QCLASS: IN (1)
	question = append(question, byte(qtype>>8), byte(qtype))
	question = append(question, 0x00, 0x01) // Class IN

	packet := append(header, question...)

	if edns {
		packet = append(packet, encodeEDNSOpt()...)
	}
	return packet, txid
}

// encodeEDNSOpt builds a minimal EDNS0 OPT pseudo-record (RFC 6891) for the
// additional section: root name, TYPE=OPT(41), CLASS=UDP payload size, zeroed
// extended-rcode/flags/version, and empty RDATA.
func encodeEDNSOpt() []byte {
	return []byte{
		0x00,       // Root domain name
		0x00, 0x29, // TYPE: OPT (41)
		byte(ednsUDPPayloadSize >> 8), byte(ednsUDPPayloadSize & 0xFF), // CLASS: UDP payload size
		0x00,       // Extended RCODE
		0x00,       // EDNS version 0
		0x00, 0x00, // Z flags
		0x00, 0x00, // RDLENGTH: 0
	}
}

// encodeDomainName converts "google.com" into DNS wire format:
// [6]google[3]com[0]
func encodeDomainName(domain string) []byte {
	var buf []byte
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00) // Root label terminator
	return buf
}

// parseDnsMessage decodes a full DNS response: header, answer records of the
// requested type, and whether an EDNS0 OPT record is present anywhere in the
// message. It handles name-pointer compression and is bounds-checked throughout.
//
// When checkTxid is set the response ID must equal wantTxid, and the QR bit must
// be set — this rejects blindly-spoofed / off-path injected packets that a
// poisoning-detection scanner must not treat as genuine answers.
func parseDnsMessage(packet []byte, qtype uint16, wantTxid uint16, checkTxid bool) (DnsHeader, []string, bool, error) {
	hdr, err := parseDnsHeader(packet)
	if err != nil {
		return DnsHeader{}, nil, false, err
	}

	if checkTxid && hdr.ID != wantTxid {
		return hdr, nil, false, fmt.Errorf("txid mismatch got=0x%04x want=0x%04x", hdr.ID, wantTxid)
	}
	if !hdr.QR {
		return hdr, nil, false, fmt.Errorf("not a response (QR=0)")
	}
	if hdr.Rcode != 0 {
		return hdr, nil, false, fmt.Errorf("dns error rcode=%d", hdr.Rcode)
	}

	offset := 12

	// Skip the question section.
	for i := 0; i < int(hdr.QDCount); i++ {
		offset = skipDnsName(packet, offset)
		if offset < 0 || offset+4 > len(packet) {
			return hdr, nil, false, fmt.Errorf("malformed question section")
		}
		offset += 4 // QTYPE (2) + QCLASS (2)
	}

	// Walk every resource record (answer + authority + additional). We collect
	// matching records from the answer section and note any OPT record (EDNS0)
	// regardless of section.
	var answers []string
	edns := false
	total := int(hdr.ANCount) + int(hdr.NSCount) + int(hdr.ARCount)
	inAnswer := int(hdr.ANCount)

	for i := 0; i < total; i++ {
		if offset >= len(packet) {
			break
		}
		offset = skipDnsName(packet, offset)
		if offset < 0 || offset+10 > len(packet) {
			break
		}

		rType := binary.BigEndian.Uint16(packet[offset : offset+2])
		offset += 2 // TYPE
		offset += 2 // CLASS (OPT: UDP payload size — ignored here)
		offset += 4 // TTL  (OPT: extended rcode/flags — ignored here)
		rdLength := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
		offset += 2

		if offset+rdLength > len(packet) {
			break
		}

		if rType == 41 { // OPT pseudo-record => resolver understood our EDNS0 query
			edns = true
		}

		if i < inAnswer && rType == qtype {
			switch qtype {
			case 1:
				if rdLength == 4 {
					answers = append(answers, fmt.Sprintf("%d.%d.%d.%d",
						packet[offset], packet[offset+1],
						packet[offset+2], packet[offset+3]))
				}
			case 16:
				if txt, err := parseTxtRData(packet[offset : offset+rdLength]); err == nil && txt != "" {
					answers = append(answers, txt)
				}
			}
		}

		offset += rdLength
	}

	if len(answers) == 0 {
		return hdr, nil, edns, fmt.Errorf("no %s records in response", dnsQueryTypeName(qtype))
	}

	return hdr, answers, edns, nil
}

func parseTxtRData(data []byte) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("empty TXT record")
	}

	parts := make([]string, 0, 4)
	for offset := 0; offset < len(data); {
		length := int(data[offset])
		offset++
		if offset+length > len(data) {
			return "", fmt.Errorf("malformed TXT record")
		}
		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}
	return strings.Join(parts, ""), nil
}

func dnsQueryTypeName(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 16:
		return "TXT"
	default:
		return fmt.Sprintf("TYPE_%d", qtype)
	}
}

// skipDnsName advances past a DNS domain name at the given offset,
// handling both label sequences and pointer compression (0xC0 prefix).
func skipDnsName(packet []byte, offset int) int {
	if offset >= len(packet) {
		return -1
	}

	for {
		if offset >= len(packet) {
			return -1
		}

		length := int(packet[offset])

		// Pointer (top 2 bits are 11)
		if length&0xC0 == 0xC0 {
			return offset + 2 // Pointer is 2 bytes, done
		}

		// Root label — end of name
		if length == 0 {
			return offset + 1
		}

		// Regular label
		offset += 1 + length
	}
}

// ════════════════════════════════════════════════════════════════════════════════
// PROTOCOL PROBES — UDP / TCP / DoT / DoH
//
// Each probe:
//   1. Builds a DNS query with randomized TXID
//   2. Connects to the resolver on the protocol-specific port
//   3. Measures TTFB (Time to First Byte)
//   4. Parses the response and validates against the truth table
// ════════════════════════════════════════════════════════════════════════════════

// DnsProbeUDPWithDialer sends a DNS A query over UDP on the specified port.
func DnsProbeUDPWithDialer(ctx context.Context, resolverIP string, domain string, truth *TruthTable, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("UDP/%d", port)}

	hdr, ips, edns, ttfb, err := probeUDPWithFallback(ctx, resolverIP, domain, 1, timeout, dialer, port)
	result.TTFB = ttfb
	if err != nil {
		result.Error = "UDP: " + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}

	result.Responded = true
	result.AnswerIPs = ips
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
	result.IsPoisoned = !truth.Verify(ips)
	return result
}

// probeUDPWithFallback sends an EDNS0 query and, if that gets no usable answer
// within half the timeout (or is refused outright), a bare query on the same
// socket. This defeats censoring middleboxes that silently drop or FORMERR
// EDNS traffic. Both queries stay valid until the one deadline, so a dead
// resolver costs one timeout, not two. Returns the response header, answers,
// whether EDNS0 is usable, the time-to-first-byte, and an error if no genuine
// answer arrived.
func probeUDPWithFallback(ctx context.Context, resolverIP string, name string, qtype uint16, timeout time.Duration, dialer *net.Dialer, port int) (DnsHeader, []string, bool, time.Duration, error) {
	addr := net.JoinHostPort(resolverIP, fmt.Sprintf("%d", port))
	conn, err := probeDialer(dialer, timeout).DialContext(ctx, "udp", addr)
	if err != nil {
		return DnsHeader{}, nil, false, 0, fmt.Errorf("DIAL: %s", truncErr(err))
	}
	defer conn.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	// Wait for a rate-limit slot before each send, so waiting never counts
	// against the resolver.
	if !waitDNSQuery(ctx, resolverIP) {
		return DnsHeader{}, nil, false, 0, fmt.Errorf("CANCELED")
	}
	query, ednsID := buildDnsQuery(name, qtype, true)
	start := time.Now()
	if _, err := conn.Write(query); err != nil {
		return DnsHeader{}, nil, false, 0, fmt.Errorf("WRITE: %s", truncErr(err))
	}
	firstWait := timeout / 2
	if limitedNetwork.Load() {
		firstWait = timeout // as before: each query gets a full timeout of its own
	}
	conn.SetReadDeadline(start.Add(firstWait))
	hdr, answers, edns, _, firstErr := readUDPResponse(conn, qtype, ednsID)
	if firstErr == nil {
		return hdr, answers, edns, time.Since(start), nil
	}
	firstPhase := time.Since(start)

	if !waitDNSQuery(ctx, resolverIP) {
		return hdr, nil, false, firstPhase, fmt.Errorf("CANCELED")
	}
	bare, bareID := buildDnsQuery(name, qtype, false)
	sent := time.Now()
	if _, err := conn.Write(bare); err != nil {
		return hdr, nil, false, firstPhase, fmt.Errorf("WRITE: %s", truncErr(err))
	}
	if limitedNetwork.Load() {
		conn.SetReadDeadline(sent.Add(timeout))
	} else {
		conn.SetReadDeadline(sent.Add(timeout - firstPhase))
	}
	h, answers, edns, id, err := readUDPResponse(conn, qtype, ednsID, bareID)
	if err == nil {
		ttfb := time.Since(sent)
		if id == ednsID { // the EDNS answer was only late
			ttfb += firstPhase
		}
		return h, answers, edns, ttfb, nil
	}
	if h.QR {
		hdr = h
	}
	if err == errUDPTimeout && firstErr != errUDPTimeout {
		err = firstErr // the resolver did answer the first query; report what was wrong with it
	}
	return hdr, nil, false, firstPhase, err
}

var errUDPTimeout = errors.New("TIMEOUT")

// readUDPResponse reads datagrams until one is a genuine response to one of
// our queries (matching TXID) or the read deadline fires. Datagrams with any
// other TXID are off-path spoofs or stragglers and are skipped: this is the
// core anti-injection guard for hostile networks. It returns the TXID that
// matched.
func readUDPResponse(conn net.Conn, qtype uint16, ids ...uint16) (DnsHeader, []string, bool, uint16, error) {
	buffer := udpResponseBuffers.Get().(*[ednsUDPPayloadSize]byte)
	defer udpResponseBuffers.Put(buffer)
	buf := buffer[:]
	for {
		n, err := conn.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return DnsHeader{}, nil, false, 0, errUDPTimeout
			}
			return DnsHeader{}, nil, false, 0, fmt.Errorf("READ: %s", truncErr(err))
		}
		if n < 2 || !slices.Contains(ids, binary.BigEndian.Uint16(buf[:2])) {
			continue // not our answer: keep waiting for the real one
		}
		id := binary.BigEndian.Uint16(buf[:2])
		hdr, answers, edns, perr := parseDnsMessage(buf[:n], qtype, id, true)
		if perr != nil {
			return hdr, nil, false, id, fmt.Errorf("PARSE: %s", perr.Error())
		}
		return hdr, answers, edns, id, nil
	}
}

// probeDialer caps the shared dialer's connect timeout at the probe timeout,
// so a short DNS timeout is not stretched by the engine-wide one.
func probeDialer(d *net.Dialer, timeout time.Duration) *net.Dialer {
	if d == nil {
		return &net.Dialer{Timeout: timeout}
	}
	if d.Timeout > 0 && d.Timeout <= timeout {
		return d
	}
	bounded := *d
	bounded.Timeout = timeout
	return &bounded
}

// DnsProbeTCP sends a DNS query over TCP/53.
// TCP DNS uses a 2-byte length prefix before the query packet.
// Often overlooked by DPI systems that only inspect UDP/53.
// DnsProbeTCPWithDialer sends a TCP-wrapped DNS query on the specified port.
func DnsProbeTCPWithDialer(ctx context.Context, resolverIP string, domain string, truth *TruthTable, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("TCP/%d", port)}

	if !waitDNSQuery(ctx, resolverIP) {
		result.Error = "CANCELED"
		return result
	}

	query, txid := buildDnsQuery(domain, 1, true)

	addr := net.JoinHostPort(resolverIP, fmt.Sprintf("%d", port))
	conn, err := probeDialer(dialer, timeout).DialContext(ctx, "tcp", addr)
	if err != nil {
		result.Error = "TCP_DIAL: " + truncErr(err)
		return result
	}
	defer conn.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	conn.SetDeadline(time.Now().Add(timeout))

	tcpMsg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(tcpMsg[:2], uint16(len(query)))
	copy(tcpMsg[2:], query)

	if _, err := conn.Write(tcpMsg); err != nil {
		result.Error = "TCP_WRITE: " + truncErr(err)
		return result
	}

	start := time.Now()
	respBuf, err := readTCPResponse(conn)
	result.TTFB = time.Since(start)
	if err != nil {
		result.Error = "TCP_READ: " + truncErr(err)
		return result
	}

	hdr, ips, edns, err := parseDnsMessage(respBuf, 1, txid, true)
	if err != nil {
		result.Error = "TCP_PARSE: " + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}

	result.Responded = true
	result.AnswerIPs = ips
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
	result.IsPoisoned = !truth.Verify(ips)
	return result
}

// readTCPResponse reads one length-prefixed DNS message from a stream
// (TCP/53 or a DoT tunnel). The 2-byte big-endian prefix bounds the body.
func readTCPResponse(conn net.Conn) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(lenBuf[:])
	// TCP/DoT frames are bounded by their uint16 prefix, not the UDP EDNS
	// payload size. Large legitimate TXT answers can exceed 4096 bytes.
	if respLen == 0 {
		return nil, fmt.Errorf("bad length %d", respLen)
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, err
	}
	return respBuf, nil
}

// DnsProbeDoT sends a DNS query over DNS-over-TLS (port 853).
// The wire format is identical to TCP DNS, but wrapped in a TLS tunnel.
// DnsProbeDoTWithDialer performs DNS-over-TLS against the resolver on the given port.
func DnsProbeDoTWithDialer(ctx context.Context, resolverIP string, domain string, truth *TruthTable, timeout time.Duration, dialer *net.Dialer, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("DoT/%d", port)}

	if !waitDNSQuery(ctx, resolverIP) {
		result.Error = "CANCELED"
		return result
	}

	query, txid := buildDnsQuery(domain, 1, true)

	addr := net.JoinHostPort(resolverIP, fmt.Sprintf("%d", port))
	tlsDialer := &tls.Dialer{NetDialer: probeDialer(dialer, timeout), Config: &tls.Config{InsecureSkipVerify: true}}
	tlsConn, err := tlsDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		result.Error = "DoT_TLS: " + truncErr(err)
		return result
	}
	defer tlsConn.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = tlsConn.Close() })
	defer stopCancel()

	tlsConn.SetDeadline(time.Now().Add(timeout))

	tcpMsg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(tcpMsg[:2], uint16(len(query)))
	copy(tcpMsg[2:], query)

	if _, err := tlsConn.Write(tcpMsg); err != nil {
		result.Error = "DoT_WRITE: " + truncErr(err)
		return result
	}

	start := time.Now()
	respBuf, err := readTCPResponse(tlsConn)
	result.TTFB = time.Since(start)
	if err != nil {
		result.Error = "DoT_READ: " + truncErr(err)
		return result
	}

	hdr, ips, edns, err := parseDnsMessage(respBuf, 1, txid, true)
	if err != nil {
		result.Error = "DoT_PARSE: " + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}

	result.Responded = true
	result.AnswerIPs = ips
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
	result.IsPoisoned = !truth.Verify(ips)
	return result
}

// DnsProbeDoH sends a DNS query via DNS-over-HTTPS (port 443).
// Uses the JSON API format (application/dns-json) for simplicity.
// DnsProbeDoHWithClient sends a DNS-over-HTTPS query using a shared HTTP client.
func DnsProbeDoHWithClient(ctx context.Context, resolverIP string, domain string, truth *TruthTable, timeout time.Duration, client *http.Client, port int) DnsProbeResult {
	result := DnsProbeResult{Protocol: fmt.Sprintf("DoH/%d", port)}

	if !waitDNSQuery(ctx, resolverIP) {
		result.Error = "CANCELED"
		return result
	}

	hdr, ips, edns, ttfb, err := dohExchange(ctx, client, resolverIP, port, domain, 1, timeout)
	result.TTFB = ttfb
	if err != nil {
		result.Error = "DoH_" + err.Error()
		result.Header, result.HeaderOK = hdr, hdr.QR
		return result
	}
	result.Responded = true
	result.AnswerIPs = ips
	result.Header, result.HeaderOK, result.EDNS = hdr, true, edns
	result.IsPoisoned = !truth.Verify(ips)
	return result
}

// dohExchange sends one RFC 8484 query (GET ?dns=, application/dns-message):
// the format every DoH server speaks. The JSON API is a Google/Cloudflare
// extra that standard servers (Quad9, OpenDNS, AdGuard, ...) reject with 400.
// The wire answer also carries the real header and EDNS0 support.
func dohExchange(ctx context.Context, client *http.Client, resolverIP string, port int, name string, qtype uint16, timeout time.Duration) (DnsHeader, []string, bool, time.Duration, error) {
	query, _ := buildDnsQuery(name, qtype, true)
	query[0], query[1] = 0, 0 // RFC 8484 4.1: ID 0 keeps answers cacheable
	url := (&neturl.URL{Scheme: "https", Host: net.JoinHostPort(resolverIP, fmt.Sprint(port)), Path: "/dns-query",
		RawQuery: "dns=" + base64.RawURLEncoding.EncodeToString(query)}).String()
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout) // the shared client uses the engine-wide timeout
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", url, nil)
	if err != nil {
		return DnsHeader{}, nil, false, 0, fmt.Errorf("REQ: %s", truncErr(err))
	}
	req.Header.Set("Accept", "application/dns-message")
	start := time.Now()
	resp, err := client.Do(req)
	ttfb := time.Since(start)
	if err != nil {
		return DnsHeader{}, nil, false, ttfb, fmt.Errorf("HTTP: %s", truncErr(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return DnsHeader{}, nil, false, ttfb, fmt.Errorf("STATUS: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return DnsHeader{}, nil, false, ttfb, fmt.Errorf("READ: %s", truncErr(err))
	}
	hdr, answers, edns, err := parseDnsMessage(body, qtype, 0, true)
	if err != nil {
		return hdr, nil, false, ttfb, fmt.Errorf("PARSE: %s", err.Error())
	}
	return hdr, answers, edns, ttfb, nil
}

// truncErr keeps an error's cause short for logs and reports. Go's wrappers
// put the operation and full address (a DoH URL with its base64 query) first,
// which used to fill the whole limit and cut the cause off.
func truncErr(err error) string {
	var urlErr *neturl.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		cause := opErr.Err
		var sysErr *os.SyscallError
		if errors.As(cause, &sysErr) {
			cause = sysErr.Err
		}
		err = fmt.Errorf("%s: %w", opErr.Op, cause)
	}
	s := err.Error()
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}
