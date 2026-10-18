package daemon

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	coredns "tross/core/dns"
	"tross/core/event"
	"tross/internal/control"
	"tross/internal/resolver"
	"tross/internal/store"
)

func canaryQuery(t *testing.T) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("use-application-dns.net."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// Без прогона имён нет нигде; прогон — через сокет команд; срок не больше
// 24 ч; выгрузка с обезличиванием; остановка демона выключает прогон.
func TestDNSDebugRun(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open("", store.DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	res, err := resolver.New(resolver.Config{Cache: coredns.NewCache(coredns.DefaultCacheParams(10)), Canary: true, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	bus := event.NewBus()
	events, unsub := bus.Subscribe(16, event.TopicDNSDebug)
	defer unsub()
	d := newDNSDebug(log, st, res, bus)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.run(ctx); close(done) }()
	dev := netip.MustParseAddr("192.168.10.30")

	res.Handle(ctx, canaryQuery(t), dev, 512) // прогона нет — не пишется
	sock := filepath.Join(t.TempDir(), "trossd.sock")
	l, err := control.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	go control.Serve(ctx, l, d.handle, log)
	if err := control.Call(sock, control.Request{Cmd: "dns-log-start", For: 25 * time.Hour}, nil); err == nil {
		t.Error("more than 24h accepted")
	}
	var stt DNSDebugStatus
	if err := control.Call(sock, control.Request{Cmd: "dns-log-start", For: time.Hour}, &stt); err != nil || !stt.Active {
		t.Fatalf("start: %+v %v", stt, err)
	}
	if !d.status().Active {
		t.Error("status must show the run")
	}
	res.Handle(ctx, canaryQuery(t), dev, 512)
	res.Handle(ctx, canaryQuery(t), netip.MustParseAddr("192.168.10.31"), 512)
	deadline := time.Now().Add(5 * time.Second)
	var rows []store.DNSDebugRow
	for len(rows) < 2 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		_ = control.Call(sock, control.Request{Cmd: "dns-log-export", Anonymize: true}, &rows)
	}
	if len(rows) != 2 || rows[0].Device != "device-1" || rows[1].Device != "device-2" || rows[0].Name != "use-application-dns.net" || rows[0].RCode != 3 {
		t.Fatalf("export: %+v — want 2 anonymized rows, written only during the run", rows)
	}
	cancel()
	<-done
	if d.status().Active {
		t.Error("daemon stop must stop the run")
	}
	var msgs []string
	for len(events) > 0 {
		msgs = append(msgs, (<-events).Data.(string))
	}
	if len(msgs) != 2 || !strings.Contains(msgs[0], "ON") || !strings.Contains(msgs[1], "OFF") {
		t.Errorf("events %v — want on and off", msgs)
	}
	closed := false
	for range 20 {
		if control.Call(sock, control.Request{Cmd: "dns-log-status"}, nil) != nil {
			closed = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !closed {
		t.Error("socket must close with the daemon")
	}
}
