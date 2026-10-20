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
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpAck      = 5
	dhcpInform   = 8
)

// ProbeMAC — chaddr пробного запроса Tross (поиск чужого DHCP-сервера):
// локальный адрес «TROSS»; в реестр не попадает.
var ProbeMAC = model.MAC{0x02, 0x54, 0x52, 0x4f, 0x53, 0x53}

// DHCPInfo — разобранное сообщение DHCP.
type DHCPInfo struct {
	Type   byte
	MAC    model.MAC
	CIAddr netip.Addr
	YIAddr netip.Addr
	// ServerID — опция 54: какой сервер ответил (у предложения и
	// подтверждения).
	ServerID netip.Addr
	Hints    model.DeviceHints
}

// FromServer — ответ сервера (предложение или подтверждение).
func (d DHCPInfo) FromServer() bool { return d.Type == dhcpOffer || d.Type == dhcpAck }

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
		case 54:
			if len(v) == 4 {
				d.ServerID = netip.AddrFrom4([4]byte(v))
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
	if d.MAC.IsZero() || d.MAC.IsMulticast() || d.MAC == ProbeMAC {
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

// Discover — пробный DHCPDISCOVER (данные UDP) от ProbeMAC: ответ
// широковещательно, так его увидит прослушивание.
func Discover(xid uint32) []byte {
	b := make([]byte, 240, 260)
	b[0], b[1], b[2] = 1, 1, 6
	binary.BigEndian.PutUint32(b[4:8], xid)
	binary.BigEndian.PutUint16(b[10:12], 0x8000)
	copy(b[28:34], ProbeMAC[:])
	binary.BigEndian.PutUint32(b[236:240], 0x63825363)
	return append(b, 53, 1, dhcpDiscover, 55, 3, 1, 3, 6, 255)
}

// IPv4UDP — датаграм с IP- и UDP-заголовками (для сокета пакетного уровня);
// контрольная сумма UDP — 0 (разрешено для IPv4).
func IPv4UDP(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	s, d := src.As4(), dst.As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], dport)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
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
