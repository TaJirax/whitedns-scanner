package configmaker

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestRewriteVmessKeepsValidAndRepointsAddress(t *testing.T) {
	orig := map[string]interface{}{
		"v": "2", "ps": "old", "add": "example.com", "port": "443",
		"id": "11111111-2222-3333-4444-555555555555", "net": "ws", "tls": "tls",
	}
	b, _ := json.Marshal(orig)
	cfg := "vmess://" + base64.StdEncoding.EncodeToString(b)

	out := rewriteConfig(cfg, "1.2.3.4:8443")
	if !strings.HasPrefix(out, "vmess://") {
		t.Fatalf("expected vmess:// output, got %q", out)
	}
	raw, ok := decodeFlexibleBase64(strings.TrimPrefix(out, "vmess://"))
	if !ok {
		t.Fatalf("output is not valid base64: %q", out)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("output is not valid vmess JSON: %v", err)
	}
	if m["add"] != "1.2.3.4" {
		t.Fatalf("add not repointed: %v", m["add"])
	}
	if m["port"] != "8443" {
		t.Fatalf("port not repointed: %v", m["port"])
	}
	if m["id"] != orig["id"] {
		t.Fatalf("uuid lost in rewrite: %v", m["id"])
	}
}

func TestRewriteConfigsKeepsAllOfMixedTypes(t *testing.T) {
	vb, _ := json.Marshal(map[string]interface{}{"add": "a.com", "port": "443", "id": "x"})
	configs := []string{
		"vless://uuid@a.com:443?security=tls#A",
		"vmess://" + base64.StdEncoding.EncodeToString(vb),
		"trojan://pw@b.com:443#B",
	}
	out := RewriteConfigs(configs, []string{"9.9.9.9:2053"})
	if len(out) != 3 {
		t.Fatalf("expected 3 rewritten configs, got %d", len(out))
	}
	// Every rewritten config must still carry its scheme and the new IP.
	for i, c := range out {
		if !strings.Contains(c, "9.9.9.9") && !strings.Contains(c, base64.StdEncoding.EncodeToString([]byte("9.9.9.9"))) {
			// vmess embeds the IP inside base64; decode to check.
			if strings.HasPrefix(c, "vmess://") {
				raw, _ := decodeFlexibleBase64(strings.TrimPrefix(c, "vmess://"))
				if !strings.Contains(string(raw), "9.9.9.9") {
					t.Fatalf("config %d did not get new IP: %q", i, c)
				}
			} else {
				t.Fatalf("config %d did not get new IP: %q", i, c)
			}
		}
	}
}
