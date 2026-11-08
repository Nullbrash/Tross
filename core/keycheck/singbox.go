package keycheck

import (
	"encoding/json"
	"errors"
)

// SingBoxConfig создаёт минимальную изолированную конфигурацию для одного выхода.
func SingBoxConfig(s OutboundSpec, port int) ([]byte, error) {
	if s.Server == "" || s.UUID == "" || s.Port < 1 || s.Port > 65535 {
		return nil, errors.New("keycheck: incomplete outbound")
	}
	outbound := map[string]any{"type": s.Type, "tag": "probe", "server": s.Server, "server_port": s.Port}
	switch s.Type {
	case "vless", "vmess":
		outbound["uuid"] = s.UUID
	case "trojan", "hysteria2":
		outbound["password"] = s.UUID
	default:
		return nil, errors.New("keycheck: unsupported outbound")
	}
	if s.Flow != "" && s.Type == "vless" {
		outbound["flow"] = s.Flow
	}
	if s.TLS {
		serverName := s.ServerName
		if serverName == "" {
			serverName = s.Server
		}
		outbound["tls"] = map[string]any{"enabled": true, "server_name": serverName, "insecure": s.Insecure}
	}
	// Hysteria2 без TLS отклоняется самим sing-box; это инвариант клиента.
	if s.Type == "hysteria2" && !s.TLS {
		return nil, errors.New("keycheck: hysteria2 requires tls")
	}
	if s.ObfsType != "" || s.ObfsPassword != "" {
		if s.Type != "hysteria2" || s.ObfsType == "" || s.ObfsPassword == "" {
			return nil, errors.New("keycheck: incomplete obfuscation settings")
		}
		outbound["obfs"] = map[string]any{"type": s.ObfsType, "password": s.ObfsPassword}
	}
	c := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "mixed", "listen": "127.0.0.1", "listen_port": port}}, "outbounds": []any{outbound, map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"final": "probe"}}
	return json.Marshal(c)
}
