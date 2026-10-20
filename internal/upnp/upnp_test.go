package upnp

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tross/core/event"
	"tross/core/model"
	coreupnp "tross/core/upnp"
	"tross/internal/dataplane"
)

var (
	pc     = netip.MustParseAddr("192.168.10.20")
	tv     = netip.MustParseAddr("192.168.10.40")
	asker  = netip.MustParseAddr("192.168.10.50")
	extIP  = netip.MustParseAddr("100.64.1.2")
	quiet  = slog.New(slog.NewTextHandler(io.Discard, nil))
	lanNet = netip.MustParsePrefix("192.168.10.0/24")
)

type fakeDevices struct {
	devs     map[netip.Addr]model.Device
	programs map[string][]string
}

func (f *fakeDevices) ByIP(a netip.Addr) (model.Device, bool) {
	d, ok := f.devs[a]
	d.UPnPPrograms = append(d.UPnPPrograms, f.programs[d.ID]...)
	return d, ok
}

func (f *fakeDevices) AllowProgram(_ context.Context, id, desc string) (model.Device, error) {
	f.programs[id] = append(f.programs[id], desc)
	for _, d := range f.devs {
		if d.ID == id {
			d.UPnPPrograms = append(d.UPnPPrograms, f.programs[id]...)
			return d, nil
		}
	}
	return model.Device{}, nil
}

func newTestService(t *testing.T) (*Service, *dataplane.Fake, *fakeDevices, <-chan event.Event) {
	t.Helper()
	devs := &fakeDevices{programs: map[string][]string{}, devs: map[netip.Addr]model.Device{
		pc:    {ID: "dev-pc", Addr: pc, UPnP: model.UPnPAllow, LastSeen: time.Now()},
		tv:    {ID: "dev-tv", Addr: tv, Type: model.DeviceTypeTV, LastSeen: time.Now()},
		asker: {ID: "dev-ask", Addr: asker, UPnP: model.UPnPAsk, LastSeen: time.Now()},
	}}
	bus := event.NewBus()
	evs, unsub := bus.Subscribe(64, event.TopicUPnP)
	t.Cleanup(unsub)
	dp := dataplane.NewFake(quiet)
	s := New(Options{Kernel: dp, Devices: devs, Log: quiet, Bus: bus, External: func() netip.Addr { return extIP },
		Online: func(d model.Device) bool { return time.Since(d.LastSeen) < 10*time.Minute },
		Taken:  func(p model.Protocol, port uint16) bool { return port == 25565 }})
	return s, dp, devs, evs
}

func next(t *testing.T, evs <-chan event.Event) event.UPnPEvent {
	t.Helper()
	select {
	case e := <-evs:
		return e.Data.(event.UPnPEvent)
	case <-time.After(time.Second):
		t.Fatal("no event")
		return event.UPnPEvent{}
	}
}

func none(t *testing.T, evs <-chan event.Event) {
	t.Helper()
	select {
	case e := <-evs:
		t.Fatalf("unexpected event %+v", e.Data)
	case <-time.After(50 * time.Millisecond):
	}
}

func req(src netip.Addr, port uint16, desc string) coreupnp.Request {
	return coreupnp.Request{Via: coreupnp.ViaIGD, Proto: model.ProtoTCP, ExtPort: port, IntPort: port, Client: src, Source: src, Lease: 30 * time.Minute, Desc: desc}
}

func TestServiceAllowDenyAsk(t *testing.T) {
	ctx := context.Background()
	s, dp, _, evs := newTestService(t)
	d, err := s.Map(ctx, req(pc, 51413, "TorrentClient"))
	if err != nil || d.Outcome != coreupnp.Allow {
		t.Fatalf("pc: %+v %v", d, err)
	}
	if e := next(t, evs); e.Action != "open" || e.ExtPort != 51413 || e.Device != "dev-pc" {
		t.Errorf("open event %+v", e)
	}
	// Продление — без события.
	s.Map(ctx, req(pc, 51413, "TorrentClient"))
	none(t, evs)
	ms, _ := dp.UPnPMappings(ctx)
	if len(ms) != 1 || ms[0].Addr != pc || ms[0].Desc != "TorrentClient" {
		t.Fatalf("kernel %+v", ms)
	}
	// ТВ (угаданный тип, уровень не задан) — отказ, повтор отказа — без события.
	if d, _ := s.Map(ctx, req(tv, 8080, "TV")); d.Outcome != coreupnp.Deny {
		t.Errorf("tv: %+v", d)
	}
	if e := next(t, evs); e.Action != "refuse" {
		t.Errorf("refuse event %+v", e)
	}
	s.Map(ctx, req(tv, 8080, "TV"))
	none(t, evs)
	// Неизвестный адрес.
	if d, _ := s.Map(ctx, req(netip.MustParseAddr("192.168.10.99"), 8080, "x")); d.Outcome != coreupnp.Deny {
		t.Errorf("unknown device: %+v", d)
	}
	next(t, evs)
	// Порт ручного проброса.
	if d, _ := s.Map(ctx, req(pc, 25565, "mc")); d.Reason != coreupnp.Conflict {
		t.Errorf("manual forward port: %+v", d)
	}
	next(t, evs)

	// «Спрашивать»: запрос ждёт, повтор не плодит записи.
	if d, _ := s.Map(ctx, req(asker, 6000, "Game")); d.Outcome != coreupnp.Ask {
		t.Fatalf("ask: %+v", d)
	}
	s.Map(ctx, req(asker, 6000, "Game"))
	if e := next(t, evs); e.Action != "ask" {
		t.Errorf("ask event %+v", e)
	}
	none(t, evs)
	p := s.Pending()
	if len(p) != 1 || p[0].Device != "dev-ask" || p[0].Desc != "Game" {
		t.Fatalf("pending %+v", p)
	}
	// «Всегда»: программа запомнена, порт открыт; следующий порт той же
	// программы — без вопроса.
	if d, err := s.Resolve(ctx, p[0].ID, "always"); err != nil || d.Outcome != coreupnp.Allow {
		t.Fatalf("always: %+v %v", d, err)
	}
	next(t, evs)
	if d, _ := s.Map(ctx, req(asker, 6001, "game")); d.Outcome != coreupnp.Allow {
		t.Errorf("program allowed always: %+v", d)
	}
	next(t, evs)
	// Отказ пользователя: сутки тот же запрос не спрашивается.
	s.Map(ctx, req(asker, 7000, "Other"))
	next(t, evs)
	id := s.Pending()[0].ID
	if _, err := s.Resolve(ctx, id, "deny"); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.Map(ctx, req(asker, 7000, "Other")); d.Outcome != coreupnp.Deny || len(s.Pending()) != 0 {
		t.Errorf("denied request asked again: %+v %v", d, s.Pending())
	}
	if _, err := s.Resolve(ctx, "nope", "once"); err != ErrNoPending {
		t.Errorf("no pending: %v", err)
	}

	// Снять можно только свой проброс.
	if err := s.Unmap(ctx, tv, model.ProtoTCP, 51413); err != ErrNotAllowed {
		t.Errorf("unmap foreign: %v", err)
	}
	if err := s.Unmap(ctx, pc, model.ProtoTCP, 51413); err != nil {
		t.Errorf("unmap own: %v", err)
	}
	if err := s.Unmap(ctx, pc, model.ProtoTCP, 51413); err != ErrNoSuchEntry {
		t.Errorf("unmap twice: %v", err)
	}
}

func TestServicePermanentAndRevoked(t *testing.T) {
	ctx := context.Background()
	s, dp, devs, _ := newTestService(t)
	r := req(pc, 51413, "TorrentClient")
	r.Lease = 0
	if d, _ := s.Map(ctx, r); !d.Permanent || d.Lease != time.Hour {
		t.Fatalf("permanent: %+v", d)
	}
	s.Map(ctx, req(pc, 6000, "short"))
	// Продление «навсегда», пока устройство в сети.
	s.tick(ctx)
	if len(s.permanent) != 1 {
		t.Errorf("permanent dropped while online")
	}
	d := devs.devs[pc]
	d.LastSeen = time.Now().Add(-time.Hour)
	devs.devs[pc] = d
	s.tick(ctx)
	if len(s.permanent) != 0 {
		t.Errorf("permanent kept for an offline device")
	}
	// Право отозвано — пробросы сняты сразу.
	d.UPnP = model.UPnPDeny
	devs.devs[pc] = d
	s.tick(ctx)
	if ms, _ := dp.UPnPMappings(ctx); len(ms) != 0 {
		t.Errorf("mappings of a denied device: %+v", ms)
	}
}

func pmpMap(op byte, in, sugg uint16, life uint32) []byte {
	b := make([]byte, 12)
	b[1] = op
	binary.BigEndian.PutUint16(b[4:6], in)
	binary.BigEndian.PutUint16(b[6:8], sugg)
	binary.BigEndian.PutUint32(b[8:12], life)
	return b
}

func TestNATPMP(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newTestService(t)
	r := HandlePMP(ctx, s, []byte{0, 0}, pc)
	if len(r) != 12 || r[1] != 128 || netip.AddrFrom4([4]byte(r[8:12])) != extIP {
		t.Fatalf("public address: %x", r)
	}
	r = HandlePMP(ctx, s, pmpMap(1, 3074, 3074, 7200), pc)
	if len(r) != 16 || r[1] != 129 || binary.BigEndian.Uint16(r[2:4]) != pmpOK || binary.BigEndian.Uint16(r[10:12]) != 3074 || binary.BigEndian.Uint32(r[12:16]) != 3600 {
		t.Fatalf("map udp: %x", r)
	}
	// Продление без подсказки — тот же внешний порт.
	r = HandlePMP(ctx, s, pmpMap(1, 3074, 0, 3600), pc)
	if binary.BigEndian.Uint16(r[10:12]) != 3074 {
		t.Errorf("renew: %x", r)
	}
	// Удаление.
	r = HandlePMP(ctx, s, pmpMap(1, 3074, 0, 0), pc)
	if own, _ := s.Owned(ctx, pc); len(own) != 0 || binary.BigEndian.Uint16(r[2:4]) != pmpOK {
		t.Errorf("delete: %x %+v", r, own)
	}
	// Запрещённое устройство.
	r = HandlePMP(ctx, s, pmpMap(2, 8080, 8080, 3600), tv)
	if r[1] != 130 || binary.BigEndian.Uint16(r[2:4]) != pmpNotAuthorized {
		t.Errorf("tv: %x", r)
	}
	if r := HandlePMP(ctx, s, []byte{0, 9}, pc); binary.BigEndian.Uint16(r[2:4]) != pmpBadOpcode {
		t.Errorf("bad opcode: %x", r)
	}
	if HandlePMP(ctx, s, []byte{0, 128, 0, 0}, pc) != nil || HandlePMP(ctx, s, []byte{0}, pc) != nil {
		t.Error("response or junk answered")
	}
}

func pcpMapReq(client netip.Addr, proto byte, in, sugg uint16, life uint32, opts ...byte) []byte {
	b := make([]byte, 60)
	b[0], b[1] = 2, 1
	binary.BigEndian.PutUint32(b[4:8], life)
	c := client.As16()
	copy(b[8:24], c[:])
	copy(b[24:36], "nonce-123456")
	b[36] = proto
	binary.BigEndian.PutUint16(b[40:42], in)
	binary.BigEndian.PutUint16(b[42:44], sugg)
	return append(b, opts...)
}

func TestPCP(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newTestService(t)
	r := HandlePMP(ctx, s, pcpMapReq(pc, 6, 51413, 51413, 7200), pc)
	if len(r) != 60 || r[1] != 0x81 || r[3] != pcpOK || binary.BigEndian.Uint32(r[4:8]) != 3600 ||
		string(r[24:36]) != "nonce-123456" || binary.BigEndian.Uint16(r[42:44]) != 51413 || netip.AddrFrom16([16]byte(r[44:60])).Unmap() != extIP {
		t.Fatalf("map: %x", r)
	}
	cases := map[string]struct {
		pkt    []byte
		src    netip.Addr
		result byte
	}{
		"address mismatch": {pcpMapReq(tv, 6, 5000, 5000, 60), pc, pcpAddrMismatch},
		"not authorized":   {pcpMapReq(tv, 6, 5000, 5000, 60), tv, pcpNotAuthorized},
		"bad protocol":     {pcpMapReq(pc, 1, 5000, 5000, 60), pc, pcpBadProto},
		"third party":      {pcpMapReq(pc, 6, 5000, 5000, 60, 1, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), pc, pcpNotAuthorized},
		"filter option":    {pcpMapReq(pc, 6, 5000, 5000, 60, 3, 0, 0, 0), pc, pcpBadOption},
		"short":            {pcpMapReq(pc, 6, 5000, 5000, 60)[:40], pc, pcpMalformed},
		"peer opcode":      {append([]byte{2, 2}, pcpMapReq(pc, 6, 5000, 5000, 60)[2:]...), pc, pcpBadOpcode},
	}
	for name, c := range cases {
		if r := HandlePMP(ctx, s, c.pkt, c.src); len(r) < 24 || r[3] != c.result {
			t.Errorf("%s: %x", name, r)
		}
	}
	// Повтор своего запроса — продление.
	if r := HandlePMP(ctx, s, pcpMapReq(pc, 6, 51413, 51413, 60), pc); r[3] != pcpOK {
		t.Errorf("renew own: %x", r)
	}
	// Удаление.
	if r := HandlePMP(ctx, s, pcpMapReq(pc, 6, 51413, 0, 0), pc); r[3] != pcpOK {
		t.Errorf("delete: %x", r)
	}
	if own, _ := s.Owned(ctx, pc); len(own) != 0 {
		t.Errorf("not deleted: %+v", own)
	}
	if r := HandlePMP(ctx, s, []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 10, 20}, pc); r[3] != pcpOK {
		t.Errorf("announce: %x", r)
	}
	if r := HandlePMP(ctx, s, []byte{1, 1, 0, 0}, pc); r[3] != pcpBadVersion {
		t.Errorf("version 1: %x", r)
	}
}

const soapEnv = `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:%s xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">%s</u:%s></s:Body></s:Envelope>`

func soap(h http.Handler, src, action, args string) *httptest.ResponseRecorder {
	body := strings.ReplaceAll(strings.ReplaceAll(soapEnv, "%s", "\x00"), "\x00", "%s")
	body = strings.Replace(body, "%s", action, 1)
	body = strings.Replace(body, "%s", args, 1)
	body = strings.Replace(body, "%s", action, 1)
	r := httptest.NewRequest("POST", "/ctl/WANIPCn", strings.NewReader(body))
	r.RemoteAddr = src + ":40000"
	r.Header.Set("SOAPACTION", `"urn:schemas-upnp-org:service:WANIPConnection:1#`+action+`"`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func addArgs(port, client, lease string) string {
	return "<NewRemoteHost></NewRemoteHost><NewExternalPort>" + port + "</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>" + port +
		"</NewInternalPort><NewInternalClient>" + client + "</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>TorrentClient</NewPortMappingDescription><NewLeaseDuration>" + lease + "</NewLeaseDuration>"
}

func TestIGD(t *testing.T) {
	s, dp, _, _ := newTestService(t)
	g := NewIGD(s, netip.MustParseAddrPort("192.168.10.1:5000"), lanNet.Contains, quiet)
	h := g.Handler()
	r := httptest.NewRequest("GET", "/rootDesc.xml", nil)
	r.RemoteAddr = "192.168.10.20:40000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "InternetGatewayDevice:1") || !strings.Contains(w.Body.String(), "/ctl/WANIPCn") {
		t.Fatalf("root desc %d %s", w.Code, w.Body)
	}
	// Не из LAN — обрыв без ответа.
	r.RemoteAddr = "203.0.113.5:40000"
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("outside LAN: answered")
			}
		}()
		h.ServeHTTP(httptest.NewRecorder(), r)
	}()
	if w := soap(h, "192.168.10.20", "AddPortMapping", addArgs("51413", "192.168.10.20", "0")); w.Code != 200 {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	if ms, _ := dp.UPnPMappings(context.Background()); len(ms) != 1 || ms[0].Lease != time.Hour {
		t.Fatalf("kernel %+v", ms)
	}
	for _, c := range []struct {
		src, action, args, want string
	}{
		{"192.168.10.20", "AddPortMapping", addArgs("6000", "192.168.10.40", "60"), "<errorCode>606</errorCode>"},
		{"192.168.10.40", "AddPortMapping", addArgs("6000", "192.168.10.40", "60"), "<errorCode>606</errorCode>"},
		{"192.168.10.20", "AddPortMapping", strings.Replace(addArgs("6000", "192.168.10.20", "60"), "<NewExternalPort>6000", "<NewExternalPort>0", 1), "<errorCode>716</errorCode>"},
		{"192.168.10.20", "AddPortMapping", strings.Replace(addArgs("6000", "192.168.10.20", "60"), "<NewRemoteHost></NewRemoteHost>", "<NewRemoteHost>1.2.3.4</NewRemoteHost>", 1), "<errorCode>726</errorCode>"},
		{"192.168.10.20", "AddPortMapping", addArgs("x", "192.168.10.20", "60"), "<errorCode>402</errorCode>"},
		{"192.168.10.20", "GetSpecificPortMappingEntry", "<NewRemoteHost></NewRemoteHost><NewExternalPort>51413</NewExternalPort><NewProtocol>TCP</NewProtocol>", "<NewInternalClient>192.168.10.20</NewInternalClient>"},
		{"192.168.10.40", "GetSpecificPortMappingEntry", "<NewRemoteHost></NewRemoteHost><NewExternalPort>51413</NewExternalPort><NewProtocol>TCP</NewProtocol>", "<errorCode>714</errorCode>"},
		{"192.168.10.20", "GetGenericPortMappingEntry", "<NewPortMappingIndex>0</NewPortMappingIndex>", "<NewExternalPort>51413</NewExternalPort>"},
		{"192.168.10.20", "GetGenericPortMappingEntry", "<NewPortMappingIndex>1</NewPortMappingIndex>", "<errorCode>713</errorCode>"},
		{"192.168.10.20", "GetExternalIPAddress", "", "<NewExternalIPAddress>100.64.1.2</NewExternalIPAddress>"},
		{"192.168.10.40", "DeletePortMapping", "<NewRemoteHost></NewRemoteHost><NewExternalPort>51413</NewExternalPort><NewProtocol>TCP</NewProtocol>", "<errorCode>606</errorCode>"},
		{"192.168.10.20", "DeletePortMapping", "<NewRemoteHost></NewRemoteHost><NewExternalPort>51413</NewExternalPort><NewProtocol>TCP</NewProtocol>", "DeletePortMappingResponse"},
		{"192.168.10.20", "DeletePortMapping", "<NewRemoteHost></NewRemoteHost><NewExternalPort>51413</NewExternalPort><NewProtocol>TCP</NewProtocol>", "<errorCode>714</errorCode>"},
		{"192.168.10.20", "Reboot", "", "<errorCode>401</errorCode>"},
	} {
		if w := soap(h, c.src, c.action, c.args); !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s from %s: %d %s, want %s", c.action, c.src, w.Code, w.Body, c.want)
		}
	}
	// Действие в заголовке не совпадает с телом.
	body := strings.NewReader(strings.Replace(soapEnv, "%s", "GetExternalIPAddress", -1))
	r = httptest.NewRequest("POST", "/ctl/WANIPCn", body)
	r.RemoteAddr = "192.168.10.20:40000"
	r.Header.Set("SOAPACTION", `"urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping"`)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "<errorCode>401</errorCode>") {
		t.Errorf("mismatched SOAPACTION: %s", w.Body)
	}
}

func TestSSDP(t *testing.T) {
	g := NewIGD(nil, netip.MustParseAddrPort("192.168.10.1:5000"), lanNet.Contains, quiet)
	all := g.SearchReplies([]byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"))
	if len(all) != 9 || !strings.Contains(string(all[0]), "LOCATION: http://192.168.10.1:5000/rootDesc.xml") {
		t.Fatalf("ssdp:all: %d %s", len(all), all)
	}
	igd := g.SearchReplies([]byte("M-SEARCH * HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"))
	if len(igd) != 1 || !strings.Contains(string(igd[0]), "::urn:schemas-upnp-org:device:InternetGatewayDevice:1") {
		t.Errorf("igd: %s", igd)
	}
	for _, q := range []string{
		"M-SEARCH * HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\nST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n",
		"M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n",
		"NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\n\r\n",
	} {
		if r := g.SearchReplies([]byte(q)); r != nil {
			t.Errorf("answered %q", q)
		}
	}
	if n := g.Notifies(true); len(n) != 9 || !strings.Contains(string(n[0]), "ssdp:alive") {
		t.Errorf("notify %s", n[0])
	}
	// Один и тот же UUID на каждом запуске для того же адреса.
	if g2 := NewIGD(nil, netip.MustParseAddrPort("192.168.10.1:5000"), lanNet.Contains, quiet); g2.uuid != g.uuid {
		t.Error("uuid not stable")
	}
}
