package upnp

import (
	"fmt"
	"strings"
)

// PortSSDP — SSDP (поиск устройств UPnP).
const PortSSDP = 1900

// ssdpTargets — что шлюз объявляет о себе: тип поиска (ST/NT) → USN.
func (g *IGD) ssdpTargets() [][2]string {
	u := func(n int) string { return fmt.Sprintf("uuid:%s-%d", g.uuid, n) }
	return [][2]string{
		{"upnp:rootdevice", u(0) + "::upnp:rootdevice"},
		{u(0), u(0)}, {u(1), u(1)}, {u(2), u(2)},
		{typeIGD, u(0) + "::" + typeIGD},
		{typeWAN, u(1) + "::" + typeWAN},
		{typeWANCon, u(2) + "::" + typeWANCon},
		{svcCommon, u(1) + "::" + svcCommon},
		{svcIPConn, u(2) + "::" + svcIPConn},
	}
}

const ssdpServer = "Linux UPnP/1.0 Tross/1"

// SearchReplies — ответы на M-SEARCH (по одному на совпавший тип); nil —
// не поиск или не про нас.
func (g *IGD) SearchReplies(b []byte) [][]byte {
	lines := strings.Split(string(b), "\n")
	if len(lines) == 0 || !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(lines[0])), "M-SEARCH * HTTP/1.1") {
		return nil
	}
	var st, man string
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch strings.ToUpper(strings.TrimSpace(k)) {
		case "ST":
			st = strings.TrimSpace(v)
		case "MAN":
			man = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	if man != "ssdp:discover" || st == "" {
		return nil
	}
	var out [][]byte
	for _, t := range g.ssdpTargets() {
		if st == "ssdp:all" || strings.EqualFold(st, t[0]) {
			out = append(out, []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: %s\r\nSERVER: %s\r\nST: %s\r\nUSN: %s\r\n\r\n",
				g.location(), ssdpServer, t[0], t[1])))
		}
	}
	return out
}

// Notifies — анонсы alive (или byebye) обо всём шлюзе.
func (g *IGD) Notifies(alive bool) [][]byte {
	nts := "ssdp:byebye"
	if alive {
		nts = "ssdp:alive"
	}
	var out [][]byte
	for _, t := range g.ssdpTargets() {
		msg := "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: " + t[0] + "\r\nNTS: " + nts + "\r\nUSN: " + t[1] + "\r\n"
		if alive {
			msg += "CACHE-CONTROL: max-age=1800\r\nLOCATION: " + g.location() + "\r\nSERVER: " + ssdpServer + "\r\n"
		}
		out = append(out, []byte(msg+"\r\n"))
	}
	return out
}
