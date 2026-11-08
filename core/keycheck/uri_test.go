package keycheck

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestParseURI(t *testing.T) {
	cases := []string{"vless://id@example.test:443?security=tls&sni=edge.example.test&flow=xtls-rprx-vision", "trojan://secret@example.test:8443", "hysteria2://secret@example.test:443?obfs=salamander&obfs-password=obfs-secret"}
	for _, raw := range cases {
		s, e := ParseURI(raw)
		if e != nil || s.Server != "example.test" || s.Port == 0 {
			t.Fatalf("%q: %#v %v", raw, s, e)
		}
	}
	if s, e := ParseURI(cases[2]); e != nil || s.ObfsType != "salamander" || s.ObfsPassword == "" {
		t.Fatalf("hysteria2 obfs: %#v %v", s, e)
	}
	vm := base64.StdEncoding.EncodeToString([]byte(`{"add":"example.test","id":"id","port":"443","tls":"tls"}`))
	if s, e := ParseURI("vmess://" + vm); e != nil || s.Type != "vmess" || !s.TLS {
		t.Fatalf("vmess: %#v %v", s, e)
	}
}

func TestSingBoxConfig(t *testing.T) {
	for _, spec := range []OutboundSpec{
		{Type: "vless", Server: "example.test", ServerName: "example.test", UUID: "id", Port: 443, TLS: true},
		{Type: "trojan", Server: "example.test", ServerName: "example.test", UUID: "secret", Port: 443, TLS: true},
		{Type: "vmess", Server: "example.test", ServerName: "example.test", UUID: "id", Port: 443, TLS: true},
		{Type: "hysteria2", Server: "example.test", ServerName: "example.test", UUID: "secret", ObfsType: "salamander", ObfsPassword: "obfs-secret", Port: 443, TLS: true},
	} {
		data, err := SingBoxConfig(spec, 18080)
		if err != nil {
			t.Fatalf("%s: %v", spec.Type, err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("%s json: %v", spec.Type, err)
		}
	}
}
