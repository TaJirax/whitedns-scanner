package engine

// target_family.go — IPv4 / IPv6 handling for scan inputs:
//   - IPv6 prefixes are sampled, not enumerated (a /32 has 2^96 addresses),
//     with the same strategy as the WhiteDNS Android app.
//   - An optional IP-family filter keeps only IPv4 or only IPv6 literals.

import (
	"bufio"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

// maxIPv6PerCIDR caps how many addresses one IPv6 prefix contributes. IPv6
// allocations are enormous and sparse, so a sequential sweep is worthless:
// the budget goes to the low addresses of a /64 (and narrower), and is spread
// across the /64 subnets of a broader prefix, on the host IDs resolvers use.
const maxIPv6PerCIDR = 256

// ipv6Sampled reports whether ipnet is an IPv6 prefix too wide to enumerate.
func ipv6Sampled(ipnet *net.IPNet) bool {
	ones, bits := ipnet.Mask.Size()
	return bits == 128 && bits-ones > 8
}

// sampleIPv6CIDR is the Android app's sampler (cleanip-finder internal/scanner).
func sampleIPv6CIDR(network *net.IPNet, limit int) []string {
	if network == nil || limit <= 0 || network.IP.To4() != nil {
		return nil
	}
	ones, bits := network.Mask.Size()
	if bits != 128 || ones < 0 {
		return nil
	}
	start := new(big.Int).SetBytes(network.IP.Mask(network.Mask).To16())
	if ones >= 64 {
		out := make([]string, 0, limit)
		cur := new(big.Int).Set(start)
		for i := 0; i < limit; i++ {
			ip := bigIntIPv6(cur)
			if ip == nil || !network.Contains(ip) {
				break
			}
			out = append(out, ip.String())
			cur.Add(cur, big.NewInt(1))
		}
		return out
	}
	variableSubnetBits := uint(64 - ones)
	maxSubnetIndex := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), variableSubnetBits), big.NewInt(1))
	subnetCount := limit
	if maxSubnetIndex.IsUint64() && maxSubnetIndex.Uint64()+1 < uint64(subnetCount) {
		subnetCount = int(maxSubnetIndex.Uint64() + 1)
	}
	commonHostIDs := []uint64{1, 0x53, 0, 2, 3, 0x35, 0x1111, 0x8888}
	out := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		subnetSlot := i % subnetCount
		hostRound := i / subnetCount
		subnetIndex := new(big.Int)
		if subnetCount > 1 {
			subnetIndex.Mul(maxSubnetIndex, big.NewInt(int64(subnetSlot)))
			subnetIndex.Div(subnetIndex, big.NewInt(int64(subnetCount-1)))
		}
		candidate := new(big.Int).Lsh(subnetIndex, 64)
		candidate.Add(candidate, start)
		hostID := commonHostIDs[hostRound%len(commonHostIDs)]
		if hostRound >= len(commonHostIDs) {
			hostID = uint64(hostRound - len(commonHostIDs) + 4)
		}
		candidate.Add(candidate, new(big.Int).SetUint64(hostID))
		ip := bigIntIPv6(candidate)
		if ip != nil && network.Contains(ip) {
			out = append(out, ip.String())
		}
	}
	return out
}

func bigIntIPv6(value *big.Int) net.IP {
	if value == nil || value.Sign() < 0 || value.BitLen() > 128 {
		return nil
	}
	raw := value.Bytes()
	full := make(net.IP, net.IPv6len)
	copy(full[len(full)-len(raw):], raw)
	return full
}

// ipv4Bounds returns an IPv4 network's first and last address as integers
// (uint64, so a /0 cannot overflow the loop that walks them).
func ipv4Bounds(ipnet *net.IPNet) (first, last uint64) {
	v4 := ipnet.IP.To4()
	ones, _ := ipnet.Mask.Size()
	first = uint64(v4[0])<<24 | uint64(v4[1])<<16 | uint64(v4[2])<<8 | uint64(v4[3])
	first &^= (uint64(1) << uint(32-ones)) - 1
	return first, first + (uint64(1) << uint(32-ones)) - 1
}

// appendIPv4 appends v as dotted-quad text without allocating.
func appendIPv4(dst []byte, v uint32) []byte {
	dst = strconv.AppendUint(dst, uint64(v>>24), 10)
	dst = append(dst, '.')
	dst = strconv.AppendUint(dst, uint64(v>>16&0xff), 10)
	dst = append(dst, '.')
	dst = strconv.AppendUint(dst, uint64(v>>8&0xff), 10)
	dst = append(dst, '.')
	return strconv.AppendUint(dst, uint64(v&0xff), 10)
}

// lineIPFamily returns "ipv4" or "ipv6" when a target line is an IP literal,
// IP endpoint, IP URL or CIDR, and "" for hostnames, comments and blanks.
func lineIPFamily(line string) string {
	value := strings.TrimSpace(line)
	if _, right, ok := strings.Cut(value, "|"); ok {
		value = strings.TrimSpace(right)
	}
	value = strings.Trim(value, `'"`)
	if value == "" || strings.HasPrefix(value, "#") {
		return ""
	}
	host := value
	if strings.Contains(value, "/") && !strings.Contains(value, "://") {
		if ip, _, err := net.ParseCIDR(value); err == nil {
			host = ip.String()
		}
	} else if strings.Contains(value, "://") {
		if u, err := url.Parse(value); err == nil {
			host = u.Hostname()
		}
	} else if h, _, err := net.SplitHostPort(value); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	switch {
	case ip == nil:
		return ""
	case ip.To4() != nil:
		return "ipv4"
	}
	return "ipv6"
}

// filterTargetFamily copies src to dst keeping only lines whose IP family
// matches (hostnames are kept; the resolver decides their addresses). It
// returns how many IP lines were kept and dropped.
func filterTargetFamily(src, dst, family string) (kept, dropped int, err error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, 0, err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return 0, 0, err
	}
	w := bufio.NewWriter(out)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch lineIPFamily(line) {
		case family:
			kept++
		case "":
			if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				kept++ // hostname
			}
		default:
			dropped++
			continue
		}
		fmt.Fprintln(w, line)
	}
	if err = sc.Err(); err == nil {
		err = w.Flush()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return kept, dropped, err
}

// targetFamilyAllows reports whether a parsed target's host passes the filter.
func targetFamilyAllows(host, family string) bool {
	if family != "ipv4" && family != "ipv6" {
		return true
	}
	got := lineIPFamily(host)
	return got == "" || got == family
}

// ipv4Span is an inclusive range of IPv4 addresses as integers.
type ipv4Span struct{ first, last uint64 }

// mergeIPv4Spans sorts spans and joins overlapping or adjacent ones, in place.
func mergeIPv4Spans(spans []ipv4Span) []ipv4Span {
	sort.Slice(spans, func(i, j int) bool { return spans[i].first < spans[j].first })
	merged := spans[:0]
	for _, s := range spans {
		if n := len(merged); n > 0 && s.first <= merged[n-1].last+1 {
			merged[n-1].last = max(merged[n-1].last, s.last)
			continue
		}
		merged = append(merged, s)
	}
	return merged
}
