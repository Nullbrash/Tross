package keycheck

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// OutboundSpec — минимальные данные для временного конфига sing-box.
// URI намеренно не сохраняется после разбора.
type OutboundSpec struct {
	Type, Server, UUID, ServerName, Flow string
	ObfsType, ObfsPassword               string
	Port                                 int
	TLS, Insecure                        bool
}

func ParseURI(raw string) (OutboundSpec, error) {
	if strings.HasPrefix(raw, "vmess://") {
		return parseVMess(strings.TrimPrefix(raw, "vmess://"))
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return OutboundSpec{}, errors.New("keycheck: invalid uri")
	}
	p := u.Port()
	if p == "" {
		p = "443"
	}
	var port int
	for _, c := range p {
		if c < '0' || c > '9' {
			return OutboundSpec{}, errors.New("keycheck: invalid port")
		}
		port = port*10 + int(c-'0')
	}
	user := u.User.Username()
	if user == "" {
		return OutboundSpec{}, errors.New("keycheck: missing credential")
	}
	t := strings.ToLower(u.Scheme)
	if t == "hy2" {
		t = "hysteria2"
	}
	switch t {
	case "vless", "trojan", "hysteria2":
	default:
		return OutboundSpec{}, errors.New("keycheck: unsupported uri")
	}
	query := u.Query()
	tls := query.Get("security") != "none"
	// Trojan и Hysteria2 используют TLS по протоколу; их нельзя запускать
	// как незашифрованное соединение даже при неполном URI.
	if t == "trojan" || t == "hysteria2" {
		tls = true
	}
	serverName := query.Get("sni")
	if serverName == "" {
		serverName = u.Hostname()
	}
	return OutboundSpec{
		Type:         t,
		Server:       u.Hostname(),
		UUID:         user,
		Port:         port,
		TLS:          tls,
		Insecure:     query.Get("insecure") == "1" || query.Get("allowInsecure") == "1",
		ServerName:   serverName,
		Flow:         query.Get("flow"),
		ObfsType:     query.Get("obfs"),
		ObfsPassword: query.Get("obfs-password"),
	}, nil
}

func parseVMess(encoded string) (OutboundSpec, error) {
	b, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(encoded)
	}
	if err != nil {
		return OutboundSpec{}, errors.New("keycheck: invalid vmess")
	}
	var v struct {
		Add  string      `json:"add"`
		ID   string      `json:"id"`
		Port json.Number `json:"port"`
		TLS  string      `json:"tls"`
		SNI  string      `json:"sni"`
		Host string      `json:"host"`
	}
	if json.Unmarshal(b, &v) != nil || v.Add == "" || v.ID == "" {
		return OutboundSpec{}, errors.New("keycheck: invalid vmess")
	}
	n, _ := v.Port.Int64()
	serverName := v.SNI
	if serverName == "" {
		serverName = v.Host
	}
	if serverName == "" {
		serverName = v.Add
	}
	return OutboundSpec{Type: "vmess", Server: v.Add, UUID: v.ID, Port: int(n), TLS: v.TLS == "tls", ServerName: serverName}, nil
}
