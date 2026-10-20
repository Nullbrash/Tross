package devices

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/dns/dnsmessage"

	"tross/core/model"
)

// Пакеты приходят от кого угодно в LAN: строки подсказок — только
// печатные и не длиннее maxHint, иначе мусор попадёт в базу и интерфейс.
const maxHint = 64

func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > maxHint {
		s = string(r[:maxHint])
	}
	return s
}

// Типы сообщений DHCP (опция 53).
const (
	dhcpDiscover = 1
	dhcpRequest  = 3
	dhcpAck      = 5
	dhcpInform   = 8
)

// DHCPInfo — разобранное сообщение DHCP.
type DHCPInfo struct {
	Type   byte
	MAC    model.MAC
	CIAddr netip.Addr
	YIAddr netip.Addr
	Hints  model.DeviceHints
}

var errNotDHCP = errors.New("devices: not a DHCP message")

// ParseDHCP разбирает сообщение DHCP (данные UDP).
func ParseDHCP(b []byte) (DHCPInfo, error) {
	const optStart = 240
	if len(b) < optStart || b[1] != 1 || b[2] != 6 || binary.BigEndian.Uint32(b[236:240]) != 0x63825363 {
		return DHCPInfo{}, errNotDHCP
	}
	var d DHCPInfo
	copy(d.MAC[:], b[28:34])
	d.CIAddr = netip.AddrFrom4([4]byte(b[12:16]))
	d.YIAddr = netip.AddrFrom4([4]byte(b[16:20]))
	for i := optStart; i < len(b); {
		code := b[i]
		if code == 255 {
			break
		}
		if code == 0 {
			i++
			continue
		}
		if i+1 >= len(b) || i+2+int(b[i+1]) > len(b) {
			return DHCPInfo{}, fmt.Errorf("devices: DHCP option %d truncated", code)
		}
		v := b[i+2 : i+2+int(b[i+1])]
		switch code {
		case 53:
			if len(v) == 1 {
				d.Type = v[0]
			}
		case 12:
			d.Hints.DHCPHostname = clean(string(v))
		case 60:
			d.Hints.DHCPVendorClass = clean(string(v))
		case 61:
			if len(v) > 0 && len(v) <= maxHint/2 {
				d.Hints.DHCPClientID = hex.EncodeToString(v)
			}
		case 55:
			ps := make([]string, len(v))
			for j, p := range v {
				ps[j] = strconv.Itoa(int(p))
			}
			d.Hints.DHCPParams = clean(strings.Join(ps, ","))
		}
		i += 2 + int(b[i+1])
	}
	if d.Type == 0 {
		return DHCPInfo{}, errNotDHCP
	}
	return d, nil
}

// Observation — наблюдение по сообщению: запросы клиента дают подсказки (и
// адрес, если клиент его уже держит), подтверждение сервера — выданный адрес.
func (d DHCPInfo) Observation(at time.Time) (Observation, bool) {
	if d.MAC.IsZero() || d.MAC.IsMulticast() {
		return Observation{}, false
	}
	o := Observation{MAC: d.MAC, At: at}
	switch d.Type {
	case dhcpDiscover, dhcpRequest, dhcpInform:
		o.Hints = d.Hints
		if !d.CIAddr.IsUnspecified() {
			o.IP = d.CIAddr
		}
	case dhcpAck:
		switch {
		case !d.YIAddr.IsUnspecified():
			o.IP = d.YIAddr
		case !d.CIAddr.IsUnspecified():
			o.IP = d.CIAddr
		default:
			return Observation{}, false
		}
	default:
		return Observation{}, false
	}
	return o, true
}

// ParseMDNS — подсказки об устройстве src из ответа mDNS: имя (запись A с
// его адресом или обратная PTR) и модель (_device-info).
func ParseMDNS(b []byte, src netip.Addr) (model.DeviceHints, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil || !h.Response {
		return model.DeviceHints{}, false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return model.DeviceHints{}, false
	}
	var out model.DeviceHints
	rev := reverseName(src)
	// handle разбирает тело записи; false — ответ испорчен, дальше не читать.
	handle := func(rh dnsmessage.ResourceHeader) bool {
		name := rh.Name.String()
		switch rh.Type {
		case dnsmessage.TypeA:
			a, err := p.AResource()
			if err != nil {
				return false
			}
			if netip.AddrFrom4(a.A) == src && out.MDNSName == "" {
				out.MDNSName = hostLabel(name)
			}
		case dnsmessage.TypePTR:
			r, err := p.PTRResource()
			if err != nil {
				return false
			}
			if strings.EqualFold(name, rev) {
				out.MDNSName = hostLabel(r.PTR.String())
			}
		case dnsmessage.TypeTXT:
			r, err := p.TXTResource()
			if err != nil {
				return false
			}
			if strings.HasSuffix(strings.ToLower(name), "._device-info._tcp.local.") {
				for _, t := range r.TXT {
					if v, ok := strings.CutPrefix(t, "model="); ok {
						out.MDNSModel = clean(v)
					}
				}
			}
		default:
			_, err := p.UnknownResource()
			return err == nil
		}
		return true
	}
	ok := true
	for ok {
		rh, err := p.AnswerHeader()
		if err != nil {
			ok = errors.Is(err, dnsmessage.ErrSectionDone)
			break
		}
		ok = handle(rh)
	}
	if ok && p.SkipAllAuthorities() == nil {
		for {
			rh, err := p.AdditionalHeader()
			if err != nil || !handle(rh) {
				break
			}
		}
	}
	return out, out != model.DeviceHints{}
}

func hostLabel(name string) string {
	name = strings.TrimSuffix(name, ".")
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".local"), ".LOCAL")
	return clean(name)
}

func reverseName(a netip.Addr) string {
	b := a.As4()
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0])
}

// ReverseQuery — запрос mDNS «имя по адресу» к самому устройству: ответ
// придёт на порт отправителя (запрос не с порта 5353 — «одноразовый»).
func ReverseQuery(a netip.Addr, id uint16) ([]byte, error) {
	name, err := dnsmessage.NewName(reverseName(a))
	if err != nil {
		return nil, err
	}
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}},
	}
	return m.Pack()
}

// ParseSSDP — заголовок SERVER из анонса или ответа SSDP.
func ParseSSDP(b []byte) (string, bool) {
	lines := strings.Split(string(b), "\n")
	if len(lines) == 0 {
		return "", false
	}
	first := strings.ToUpper(strings.TrimSpace(lines[0]))
	if !strings.HasPrefix(first, "NOTIFY ") && !strings.HasPrefix(first, "HTTP/1.1 200") {
		return "", false
	}
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(l, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), "server") {
			if v = clean(v); v != "" {
				return v, true
			}
		}
	}
	return "", false
}
