package configmaker

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

const amneziaWGConf = `[Interface]
PrivateKey = aFakePrivateKeyValueForTests000000000000000=
Address = 10.8.0.2/32
DNS = 1.1.1.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 76
S2 = 41
H1 = 1234567890
H2 = 987654321
H3 = 111222333
H4 = 444555666

[Peer]
PublicKey = aFakePublicKeyValueForTests00000000000000000=
PresharedKey = aFakePresharedKeyForTests00000000000000000 0=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.7:51820
PersistentKeepalive = 25`

func TestExtractConfigsKeepsWireguardBlockWhole(t *testing.T) {
	got := ExtractConfigs(amneziaWGConf)
	if len(got) != 1 {
		t.Fatalf("expected 1 config, got %d: %#v", len(got), got)
	}
	if !strings.Contains(got[0], "[Peer]") || !strings.Contains(got[0], "Jc = 4") {
		t.Fatalf("block was split or truncated:\n%s", got[0])
	}
}

func TestExtractConfigsSeparatesWireguardFromURIConfigs(t *testing.T) {
	raw := amneziaWGConf + "\n\nvless://uuid@a.com:443?type=ws&security=tls#A\ntrojan://pw@b.com:443#B\n"
	got := ExtractConfigs(raw)
	if len(got) != 3 {
		t.Fatalf("expected 3 configs (1 wg + 2 uri), got %d: %#v", len(got), got)
	}
	if !IsWireguardConfig(got[0]) {
		t.Fatalf("first config should be the WireGuard block, got %q", got[0])
	}
	// The URI lines must not have been absorbed into the INI block: "?type=ws"
	// contains "=", which a naive INI key test would accept.
	if strings.Contains(got[0], "vless://") {
		t.Fatalf("vless line swallowed into the WireGuard block:\n%s", got[0])
	}
	if !strings.HasPrefix(got[1], "vless://") || !strings.HasPrefix(got[2], "trojan://") {
		t.Fatalf("URI configs not extracted: %#v", got[1:])
	}
}

func TestRewriteWireguardRepointsEndpointAndKeepsEverythingElse(t *testing.T) {
	out := rewriteConfig(amneziaWGConf, "198.51.100.9:2408")

	if !strings.Contains(out, "Endpoint = 198.51.100.9:2408") {
		t.Fatalf("endpoint not repointed:\n%s", out)
	}
	if strings.Contains(out, "203.0.113.7") {
		t.Fatalf("old endpoint still present:\n%s", out)
	}
	// Every other line has to survive byte-for-byte, obfuscation keys included:
	// dropping one silently breaks the AmneziaWG handshake.
	for _, keep := range []string{
		"Jc = 4", "Jmin = 40", "Jmax = 70", "S1 = 76", "S2 = 41",
		"H1 = 1234567890", "H4 = 444555666",
		"PrivateKey = aFakePrivateKeyValueForTests000000000000000=",
		"AllowedIPs = 0.0.0.0/0, ::/0", "PersistentKeepalive = 25",
	} {
		if !strings.Contains(out, keep) {
			t.Fatalf("lost %q in rewrite:\n%s", keep, out)
		}
	}
	if !IsAmneziaWGConfig(out) {
		t.Fatal("rewritten config no longer detected as AmneziaWG")
	}
}

func TestRewriteWireguardAddsMissingEndpoint(t *testing.T) {
	conf := "[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = p\nAllowedIPs = 0.0.0.0/0"
	out := rewriteConfig(conf, "198.51.100.9:2408")
	if !strings.Contains(out, "Endpoint = 198.51.100.9:2408") {
		t.Fatalf("endpoint not added:\n%s", out)
	}
	// It must land inside [Peer]; an Endpoint under [Interface] is invalid.
	peer := strings.Index(out, "[Peer]")
	endpoint := strings.Index(out, "Endpoint =")
	if peer < 0 || endpoint < peer {
		t.Fatalf("endpoint not placed inside [Peer]:\n%s", out)
	}
}

func TestRewriteConfigsRoundTripsMultipleWireguardBlocks(t *testing.T) {
	raw := amneziaWGConf + "\n\n" + amneziaWGConf
	configs := ExtractConfigs(raw)
	if len(configs) != 1 {
		// Identical blocks de-duplicate; use distinct ones to test the joining.
		t.Logf("de-duplicated to %d config(s), as expected", len(configs))
	}
	second := strings.Replace(amneziaWGConf, "10.8.0.2/32", "10.8.0.3/32", 1)
	configs = ExtractConfigs(amneziaWGConf + "\n\n" + second)
	if len(configs) != 2 {
		t.Fatalf("expected 2 distinct blocks, got %d", len(configs))
	}

	out := RewriteConfigs(configs, []string{"198.51.100.9:2408", "198.51.100.10:443"})
	joined := strings.Join(out, "\n")
	// The written file must parse back into the same two configs, or a user
	// cannot feed the output back in.
	back := ExtractConfigs(joined)
	if len(back) != 2 {
		t.Fatalf("rewritten output did not re-parse into 2 configs, got %d:\n%s", len(back), joined)
	}
	if !strings.Contains(joined, "198.51.100.9:2408") || !strings.Contains(joined, "198.51.100.10:443") {
		t.Fatalf("both targets should be used:\n%s", joined)
	}
}

func TestExtractIPsFindsWireguardEndpoint(t *testing.T) {
	got := ExtractIPs(amneziaWGConf + "\nvless://uuid@9.9.9.9:2053#X\n")
	want := map[string]bool{"203.0.113.7:51820": false, "9.9.9.9:2053": false}
	for _, ip := range got {
		if _, ok := want[ip]; ok {
			want[ip] = true
		}
	}
	for ip, found := range want {
		if !found {
			t.Fatalf("missing %s in extracted endpoints: %#v", ip, got)
		}
	}
}

func TestWireguardEndpointIgnoresHostnamesAndComments(t *testing.T) {
	if got := wireguardEndpoint("[Peer]\nEndpoint = vpn.example.com:51820"); got != "" {
		t.Fatalf("hostname endpoint should not be reported as an IP, got %q", got)
	}
	got := wireguardEndpoint("[Peer]\nEndpoint = 203.0.113.7:51820 # main\n")
	if got != "203.0.113.7:51820" {
		t.Fatalf("inline comment not stripped, got %q", got)
	}
}

// makeAmneziaLink builds a vpn:// share link in the qCompress envelope Amnezia
// itself emits, so the decode path is exercised the way a real config hits it.
func makeAmneziaLink(t *testing.T, payload map[string]interface{}) string {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(data))); err != nil {
		t.Fatalf("length prefix: %v", err)
	}
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("compress: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return "vpn://" + base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

func amneziaPayload() map[string]interface{} {
	return map[string]interface{}{
		"hostName":         "203.0.113.7",
		"defaultContainer": "amnezia-awg",
		"description":      "My Server",
		"containers": []interface{}{
			map[string]interface{}{
				"container": "amnezia-awg",
				"awg": map[string]interface{}{
					"port":            "51820",
					"transport_proto": "udp",
					"last_config":     `{"config_version":2,"config":"` + strings.ReplaceAll(amneziaWGConf, "\n", `\n`) + `"}`,
				},
			},
		},
	}
}

func TestRewriteAmneziaRepointsHostPortAndEmbeddedConfig(t *testing.T) {
	link := makeAmneziaLink(t, amneziaPayload())

	out := rewriteConfig(link, "198.51.100.9:2408")
	if !strings.HasPrefix(out, "vpn://") {
		t.Fatalf("expected a vpn:// link back, got %q", out)
	}
	if out == link {
		t.Fatal("link unchanged by rewrite")
	}

	data, qCompressed, ok := decodeAmnezia(out)
	if !ok {
		t.Fatalf("rewritten link does not decode: %q", out)
	}
	if !qCompressed {
		t.Fatal("envelope changed: Amnezia's qCompress prefix was dropped")
	}
	var got map[string]interface{}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("rewritten payload is not JSON: %v", err)
	}
	if got["hostName"] != "198.51.100.9" {
		t.Fatalf("hostName not repointed: %v", got["hostName"])
	}
	if got["description"] != "My Server" {
		t.Fatalf("unrelated field lost: %v", got["description"])
	}

	awg := got["containers"].([]interface{})[0].(map[string]interface{})["awg"].(map[string]interface{})
	if awg["port"] != "2408" {
		t.Fatalf("container port not repointed: %v", awg["port"])
	}
	if awg["transport_proto"] != "udp" {
		t.Fatalf("unrelated container field lost: %v", awg["transport_proto"])
	}
	// The container's embedded copy of the WireGuard config has to move too,
	// or the client dials the old address despite the updated hostName.
	var lastConfig map[string]interface{}
	if err := json.Unmarshal([]byte(awg["last_config"].(string)), &lastConfig); err != nil {
		t.Fatalf("last_config is not JSON: %v", err)
	}
	inner := lastConfig["config"].(string)
	if !strings.Contains(inner, "Endpoint = 198.51.100.9:2408") {
		t.Fatalf("embedded WireGuard endpoint not repointed:\n%s", inner)
	}
	if !strings.Contains(inner, "Jc = 4") {
		t.Fatalf("embedded obfuscation parameters lost:\n%s", inner)
	}
}

func TestAmneziaEndpointReadsEmbeddedWireguardEndpoint(t *testing.T) {
	link := makeAmneziaLink(t, amneziaPayload())
	if got := HostPort(link); got != "203.0.113.7:51820" {
		t.Fatalf("HostPort(vpn://...) = %q, want 203.0.113.7:51820", got)
	}
	if got := ExtractIPs(link); len(got) != 1 || got[0] != "203.0.113.7:51820" {
		t.Fatalf("ExtractIPs(vpn://...) = %#v", got)
	}
}

func TestRewriteAmneziaLeavesUndecodableLinkAlone(t *testing.T) {
	// A truncated or foreign vpn:// link must pass through untouched rather
	// than be replaced with corrupt output.
	bad := "vpn://not-a-real-payload"
	if got := rewriteConfig(bad, "198.51.100.9:2408"); got != bad {
		t.Fatalf("undecodable link was mangled: %q", got)
	}
}

func TestWireguardURIFormIsStillRewrittenAsAURL(t *testing.T) {
	uri := "wireguard://cHJpdmF0ZWtleQ%3D%3D@203.0.113.7:51820?address=10.8.0.2%2F32#Old"
	out := rewriteConfig(uri, "198.51.100.9:2408")
	if !strings.Contains(out, "198.51.100.9:2408") {
		t.Fatalf("wireguard:// URI not repointed: %q", out)
	}
	if !strings.Contains(out, "cHJpdmF0ZWtleQ") {
		t.Fatalf("private key lost from wireguard:// URI: %q", out)
	}
	if got := ExtractConfigs(uri); len(got) != 1 || got[0] != uri {
		t.Fatalf("wireguard:// URI not extracted: %#v", got)
	}
}
