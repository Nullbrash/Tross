//go:build linux

package linkmon

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"tross/core/event"
	"tross/core/linkhealth"
	"tross/core/model"
)

// System — монитор каналов: ICMP- и TCP-пробы через каждый канал (метка +
// привязка к интерфейсу), гистерезис core/linkhealth, HTTP-проверка,
// пассивная и активная скорость.
type System struct {
	opts  Options
	links []*link
	// probeBytes — байты проб (запросы и ответы, с IP-заголовком): трафик
	// мониторинга, важный для лимитированных каналов.
	probeBytes atomic.Uint64
}

type link struct {
	probe  LinkProbe
	pinger *pinger // создаётся лениво: интерфейса может ещё не быть

	mu       sync.Mutex
	tracker  *linkhealth.Tracker
	health   model.LinkHealth
	peak     linkhealth.PeakTracker
	lastRx   uint64
	lastTx   uint64
	lastAt   time.Time
	active   model.Throughput
	lastAuto time.Time
	rounds   int

	testing  atomic.Bool
	httpBusy atomic.Bool
	http     *http.Client // HTTP-проверка через канал; создаётся лениво
}

var _ LinkMonitor = (*System)(nil)

func NewSystem(opts Options, probes []LinkProbe) (LinkMonitor, error) {
	if opts.Interval <= 0 || opts.Timeout <= 0 || opts.Timeout > opts.Interval {
		return nil, errors.New("linkmon: need 0 < timeout <= interval")
	}
	if len(opts.TCPTargets) == 0 {
		return nil, errors.New("linkmon: no TCP probe targets")
	}
	s := &System{opts: opts}
	for _, p := range probes {
		if len(p.Targets) == 0 {
			return nil, fmt.Errorf("linkmon: link %s has no probe targets", p.Link.ID)
		}
		s.links = append(s.links, &link{
			probe:   p,
			tracker: linkhealth.NewTracker(opts.Params),
			health:  model.LinkHealth{LinkID: p.Link.ID, State: model.LinkStateUnknown},
		})
	}
	return s, nil
}

func (s *System) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, l := range s.links {
		wg.Go(func() { s.loop(ctx, l) })
	}
	wg.Wait()
	for _, l := range s.links {
		if l.pinger != nil {
			l.pinger.close()
		}
	}
	return nil
}

func (s *System) loop(ctx context.Context, l *link) {
	t := time.NewTicker(s.opts.Interval)
	defer t.Stop()
	for {
		s.round(ctx, l)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *System) round(ctx context.Context, l *link) {
	now := time.Now()
	r := linkhealth.Round{At: now, Sent: len(l.probe.Targets), WLSent: len(l.probe.Whitelist)}
	// Сокет привязан к индексу интерфейса: пересозданный интерфейс (USB-модем,
	// телефон) — новый индекс, и старый сокет молчал бы навсегда.
	if l.pinger != nil && !l.pinger.boundTo(l.probe.Link.Interface) {
		s.opts.Log.Info("linkmon: interface recreated or gone, reopening probe socket", "link", l.probe.Link.ID)
		l.pinger.close()
		l.pinger = nil
	}
	if l.pinger == nil {
		p, err := newPinger(l.probe.Link.Interface, l.probe.Mark, &s.probeBytes)
		if err != nil {
			s.opts.Log.Debug("linkmon: no pinger yet", "link", l.probe.Link.ID, "err", err)
		}
		l.pinger = p
	}
	type tcpRes struct {
		rtt time.Duration
		ok  bool
	}
	// На лимитированном канале регулярная TCP-проба — раз в tcpEveryMetered
	// раундов (~250–350 Б за пробу, ~13 МБ/сутки при каждом раунде).
	every := 1
	if l.probe.Link.Metered {
		every = tcpEveryMetered
	}
	target := s.opts.TCPTargets[l.rounds%len(s.opts.TCPTargets)]
	probe := func() tcpRes {
		rtt, ok := s.tcpProbe(ctx, l, target)
		return tcpRes{rtt, ok}
	}
	tcpDone := make(chan tcpRes, 1)
	regular := l.rounds%every == 0
	if regular {
		go func() { tcpDone <- probe() }()
	}
	if l.pinger != nil {
		type res struct {
			dst netip.Addr
			rtt time.Duration
			ok  bool
			wl  bool
		}
		all := len(l.probe.Targets) + len(l.probe.Whitelist)
		ch := make(chan res, all)
		send := func(dst netip.Addr, wl bool) {
			rtt, ok := l.pinger.ping(ctx, dst, s.opts.Timeout)
			ch <- res{dst, rtt, ok, wl}
		}
		for _, a := range l.probe.Targets {
			go send(a, false)
		}
		for _, a := range l.probe.Whitelist {
			go send(a, true)
		}
		for range all {
			x := <-ch
			switch {
			case x.ok && x.wl:
				r.WLRecv++
			case x.ok:
				r.Recv++
				r.RTTs = append(r.RTTs, linkhealth.Sample{Target: x.dst.String(), RTT: x.rtt})
			}
		}
	}
	// TCP-проба каждый раунд (цели по кругу): ICMP может проходить, когда TCP
	// режется, и наоборот. Шла параллельно с ICMP — ждём её здесь.
	var tcp tcpRes
	tcpSample := func() linkhealth.Sample { return linkhealth.Sample{Target: "tcp " + target.String(), RTT: tcp.rtt} }
	switch {
	case regular:
		tcp = <-tcpDone
	case r.Recv == 0:
		tcp = probe() // ICMP молчит — TCP как запасная проба всегда
	}
	switch {
	case r.Recv > 0 && !regular:
	case r.Recv > 0:
		// Стабильно падающий TCP при живом ICMP поднимает потери окна → degraded.
		r.Sent++
		if tcp.ok {
			r.Recv++
			r.RTTs = append(r.RTTs, tcpSample())
		}
	case tcp.ok:
		// ICMP режется по пути — раунд засчитывается одной TCP-пробой, иначе
		// потери 75 % держали бы канал в degraded.
		r.Sent, r.Recv, r.RTTs = 1, 1, []linkhealth.Sample{tcpSample()}
	}

	l.mu.Lock()
	prev, _, _ := l.tracker.State()
	m, changed := l.tracker.Observe(r)
	state, since, reason := l.tracker.State()
	down, up := s.passiveLocked(l, now)
	l.health = model.LinkHealth{
		LinkID: l.probe.Link.ID, State: state, StateSince: since,
		RTT: m.RTT, Jitter: m.Jitter, Loss: m.Loss,
		Throughput: combineThroughput(now, down, up, l.active),
		RxBytes:    l.lastRx, TxBytes: l.lastTx,
		UpdatedAt: now, Reason: reason,
	}
	due := !l.probe.Link.Metered && state.Usable() &&
		nightlyDue(now, l.lastAuto, s.opts.SpeedTest.Hour, s.opts.SpeedTest.Minute)
	if due {
		l.lastAuto = now
	}
	httpDue := len(s.opts.HTTPCheck.URLs) > 0 && l.tracker.HTTPRelevant() &&
		l.rounds%max(1, int(s.opts.HTTPCheck.Interval/s.opts.Interval)) == 0
	l.rounds++
	l.mu.Unlock()

	if changed {
		s.publish(l, now, prev, state, reason)
	}
	if due {
		go func() {
			th, err := s.SpeedTest(ctx, l.probe.Link.ID)
			s.opts.Log.Info("nightly speed test", "link", l.probe.Link.ID, "down_bps", th.DownBps, "err", err)
		}()
	}
	// Отдельно от раунда: запросы с DNS и TLS не должны сбивать ритм проб.
	if httpDue && l.httpBusy.CompareAndSwap(false, true) {
		go func() {
			defer l.httpBusy.Store(false)
			s.httpCheck(ctx, l)
		}()
	}
}

func (s *System) publish(l *link, at time.Time, from, to model.LinkState, reason string) {
	s.opts.Log.Info("link state", "link", l.probe.Link.ID, "from", from, "to", to, "reason", reason)
	s.opts.Bus.Publish(event.Event{Topic: event.TopicLinkState, Time: at,
		Data: event.LinkStateChange{Link: l.probe.Link.ID, From: from, To: to, Reason: reason}})
}

// httpCheck — достаточно одного адреса с ожидаемым ответом; подмена ответа
// (страница авторизации) или тишина по всем — неудача.
func (s *System) httpCheck(ctx context.Context, l *link) {
	o := s.opts.HTTPCheck
	if l.http == nil {
		l.http = s.linkHTTPClient(l, o.Timeout)
	}
	ok, why := false, ""
	for _, u := range o.URLs {
		if u.Domestic {
			continue
		}
		if err := checkURL(ctx, l.http, u); err != nil {
			why = err.Error()
			continue
		}
		ok, why = true, ""
		break
	}
	if !ok {
		// Российские адреса не дают «интернет есть», но различают причину.
		for _, u := range o.URLs {
			if u.Domestic && checkURL(ctx, l.http, u) == nil {
				why = "only domestic sites answer (operator whitelist?); " + why
				break
			}
		}
	}
	now := time.Now()
	l.mu.Lock()
	prev, _, _ := l.tracker.State()
	changed := l.tracker.ObserveHTTP(now, ok, why)
	state, since, reason := l.tracker.State()
	l.health.State, l.health.StateSince, l.health.Reason = state, since, reason
	l.mu.Unlock()
	if changed {
		s.publish(l, now, prev, state, reason)
	}
}

func checkURL(ctx context.Context, c *http.Client, u HTTPCheckURL) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.URL, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	// Status 0 — любой ответ: для российских https-адресов важен сам факт
	// настоящего TLS-рукопожатия.
	if u.Status != 0 && resp.StatusCode != u.Status {
		return fmt.Errorf("%s: status %d, want %d", req.URL.Host, resp.StatusCode, u.Status)
	}
	if u.Body != "" && !strings.Contains(string(body), u.Body) {
		return fmt.Errorf("%s: unexpected body", req.URL.Host)
	}
	return nil
}

// linkHTTPClient — HTTP через канал: соединения и DNS-запросы с меткой канала,
// перенаправления не выполняются (страница авторизации отвечает именно ими).
func (s *System) linkHTTPClient(l *link, timeout time.Duration) *http.Client {
	ctl := sockopts(l.probe.Link.Interface, l.probe.Mark)
	linkDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: timeout, Control: ctl}
		return d.DialContext(ctx, network, addr)
	}
	h := s.opts.HTTPCheck
	resolver := &net.Resolver{PreferGo: true, Dial: resolverDial(h.DNS, linkDial, h.RootCAs, timeout)}
	dialer := &net.Dialer{Timeout: timeout, Control: ctl, Resolver: resolver}
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp4", addr)
			},
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: timeout,
		},
	}
}

// passiveLocked — скорость по счётчикам интерфейса между раундами.
func (s *System) passiveLocked(l *link, now time.Time) (down, up uint64) {
	nl, err := netlink.LinkByName(l.probe.Link.Interface)
	if err != nil || nl.Attrs().Statistics == nil {
		return l.peak.Peak(now)
	}
	st := nl.Attrs().Statistics
	if !l.lastAt.IsZero() && st.RxBytes >= l.lastRx && st.TxBytes >= l.lastTx {
		dt := now.Sub(l.lastAt).Seconds()
		if dt > 0 {
			l.peak.Add(now, uint64(float64(st.RxBytes-l.lastRx)*8/dt), uint64(float64(st.TxBytes-l.lastTx)*8/dt))
		}
	}
	l.lastRx, l.lastTx, l.lastAt = st.RxBytes, st.TxBytes, now
	return l.peak.Peak(now)
}

func (s *System) tcpProbe(ctx context.Context, l *link, dst netip.AddrPort) (time.Duration, bool) {
	d := net.Dialer{Timeout: s.opts.Timeout, Control: sockopts(l.probe.Link.Interface, l.probe.Mark)}
	start := time.Now()
	c, err := d.DialContext(ctx, "tcp4", dst.String())
	rtt := time.Since(start)
	if err == nil {
		c.Close()
		return rtt, true
	}
	// Отказ в соединении (RST) — тоже ответ: путь до цели работает.
	return rtt, errors.Is(err, syscall.ECONNREFUSED)
}

func (s *System) find(id model.LinkID) *link {
	for _, l := range s.links {
		if l.probe.Link.ID == id {
			return l
		}
	}
	return nil
}

func (s *System) Snapshot() []model.LinkStatus {
	out := make([]model.LinkStatus, 0, len(s.links))
	for _, l := range s.links {
		l.mu.Lock()
		out = append(out, model.LinkStatus{Link: l.probe.Link, Health: l.health})
		l.mu.Unlock()
	}
	return out
}

func (s *System) Status(id model.LinkID) (model.LinkStatus, bool) {
	l := s.find(id)
	if l == nil {
		return model.LinkStatus{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return model.LinkStatus{Link: l.probe.Link, Health: l.health}, true
}

// ProbeBytes — сколько байт проб отправлено и получено с запуска.
func (s *System) ProbeBytes() uint64 { return s.probeBytes.Load() }

func (s *System) SpeedTest(ctx context.Context, id model.LinkID) (model.Throughput, error) {
	l := s.find(id)
	if l == nil {
		return model.Throughput{}, fmt.Errorf("unknown link %q", id)
	}
	if !l.testing.CompareAndSwap(false, true) {
		return model.Throughput{}, fmt.Errorf("speed test on %s is already running", id)
	}
	defer l.testing.Store(false)

	o := s.opts.SpeedTest
	ctx, cancel := context.WithTimeout(ctx, o.Duration+10*time.Second)
	defer cancel()
	// Соединения переиспользуются: каждый новый запрос не начинает разгон TCP заново.
	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, Control: sockopts(l.probe.Link.Interface, l.probe.Mark)}).DialContext,
		MaxIdleConnsPerHost: speedStreams,
		ForceAttemptHTTP2:   true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	var th model.Throughput
	var lastErr error
	for _, url := range o.URLs {
		var total atomic.Int64
		start := time.Now()
		deadline := start.Add(o.Duration)
		errs := make(chan error, speedStreams)
		var wg sync.WaitGroup
		for range speedStreams {
			wg.Go(func() { errs <- speedStream(ctx, client, url, deadline, o.MaxBytes, &total) })
		}
		wg.Wait()
		close(errs)
		var bad, other error
		for err := range errs {
			switch {
			case errors.Is(err, ErrTransferFrozen), errors.Is(err, ErrStubResponse):
				bad = err
			case err != nil:
				other = err
			}
		}
		// Застывшая передача или заглушка вместо данных — признак блокировки
		// источника, а не скорости канала: такой замер не засчитывается,
		// берётся следующий источник.
		if bad == nil && total.Load() > 0 {
			th = model.Throughput{DownBps: uint64(float64(total.Load()) * 8 / time.Since(start).Seconds()), MeasuredAt: time.Now()}
			break
		}
		lastErr = fmt.Errorf("%s: %w", url, cmp.Or(bad, other, errors.New("no data")))
		s.opts.Log.Warn("speed test source failed, trying next", "link", id, "err", lastErr)
	}
	if th.MeasuredAt.IsZero() {
		return model.Throughput{}, fmt.Errorf("speed test %s: no usable source: %w", id, lastErr)
	}
	l.mu.Lock()
	l.active = th
	l.health.Throughput = combineThroughput(th.MeasuredAt, l.health.Throughput.DownBps, l.health.Throughput.UpBps, th)
	l.mu.Unlock()
	return th, nil
}

// speedStreams — параллельных потоков замера. Не больше двух: DPI может
// «заморозить» больше 3 TLS-сессий к одному имени за минуту; соединения
// потоков переиспользуются между запросами.
const speedStreams = 2

const tcpEveryMetered = 5

// stallAfter — нагруженный поток без единого байта столько времени застыл:
// работающий канал, даже медленный, так не замирает; типичный случай — блок
// источника «после ~25 пакетов» (12–36 КБ).
const stallAfter = 3 * time.Second

var ErrTransferFrozen = errors.New("transfer froze early — source likely blocked (DPI), not a slow link")

// minResponse — ответ короче этого — не тестовые данные, а заглушка:
// страница авторизации или блокировки провайдера, «ok» вместо файла.
// Источники теста скорости отдают мегабайты на запрос.
const minResponse = 64 << 10

var ErrStubResponse = errors.New("source answered with a short page, not test data — likely captive portal or block page")

// speedStream повторяет запросы, пока не истечёт срок или не наберётся
// общий предел. Повтор нужен: сервер ограничивает объём одного ответа
// (speed.cloudflare.com отдаёт 403 на ≥ 100 МБ).
func speedStream(ctx context.Context, c *http.Client, url string, deadline time.Time, maxBytes int64, total *atomic.Int64) error {
	buf := make([]byte, 64<<10)
	for time.Now().Before(deadline) && total.Load() < maxBytes {
		got, stalled, err := speedRequest(ctx, c, url, deadline, maxBytes, total, buf)
		switch {
		case stalled:
			return fmt.Errorf("%w (after %d KB in this response)", ErrTransferFrozen, got>>10)
		case err != nil:
			return err
		}
	}
	return nil
}

// speedRequest — один запрос со сторожем: нет данных stallAfter — запрос
// отменяется и помечается застывшим.
func speedRequest(ctx context.Context, c *http.Client, url string, deadline time.Time, maxBytes int64, total *atomic.Int64, buf []byte) (got int64, stalled bool, err error) {
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var froze atomic.Bool
	watchdog := time.NewTicker(250 * time.Millisecond)
	defer watchdog.Stop()
	go func() {
		for {
			select {
			case <-rctx.Done():
				return
			case <-watchdog.C:
				if time.Since(time.Unix(0, last.Load())) > stallAfter {
					froze.Store(true)
					cancel()
					return
				}
			}
		}
	}()

	req, err := http.NewRequestWithContext(rctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, froze.Load(), err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	for time.Now().Before(deadline) && total.Load() < maxBytes {
		k, err := resp.Body.Read(buf)
		if k > 0 {
			got += int64(k)
			total.Add(int64(k))
			last.Store(time.Now().UnixNano())
		}
		if err == io.EOF {
			if got < minResponse {
				return got, false, fmt.Errorf("%w (%d bytes)", ErrStubResponse, got)
			}
			return got, false, nil
		}
		if err != nil {
			return got, froze.Load(), err
		}
	}
	return got, false, nil
}

// sockopts — сокет идёт через канал: метка выбирает его таблицу маршрутизации,
// привязка к интерфейсу не даёт уйти в другой при ошибке маршрутов.
func sockopts(iface string, mark uint32) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark)); serr != nil {
				return
			}
			serr = unix.BindToDevice(int(fd), iface)
		})
		return errors.Join(err, serr)
	}
}

// pinger — raw ICMP-сокет одного канала; ответы сопоставляются по ID и Seq.
type pinger struct {
	conn    *net.IPConn
	id      int
	ifindex int // интерфейс на момент привязки
	bytes   *atomic.Uint64

	mu   sync.Mutex
	seq  uint16
	wait map[uint16]chan time.Time
}

const ipHeader = 20

var probePayload = []byte("trossprb")

func newPinger(iface string, mark uint32, counter *atomic.Uint64) (*pinger, error) {
	nl, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: sockopts(iface, mark)}
	pc, err := lc.ListenPacket(context.Background(), "ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	p := &pinger{conn: pc.(*net.IPConn), id: rand.IntN(0xffff) + 1, ifindex: nl.Attrs().Index, bytes: counter, wait: map[uint16]chan time.Time{}}
	go p.readLoop()
	return p, nil
}

func (p *pinger) close() { p.conn.Close() }

// boundTo — интерфейс с этим именем всё ещё тот, к которому привязан сокет.
func (p *pinger) boundTo(iface string) bool {
	nl, err := netlink.LinkByName(iface)
	return err == nil && nl.Attrs().Index == p.ifindex
}

func (p *pinger) readLoop() {
	buf := make([]byte, 1500)
	for {
		n, _, err := p.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		at := time.Now()
		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok || echo.ID != p.id {
			continue
		}
		p.bytes.Add(uint64(n + ipHeader))
		p.mu.Lock()
		ch := p.wait[uint16(echo.Seq)]
		delete(p.wait, uint16(echo.Seq))
		p.mu.Unlock()
		if ch != nil {
			ch <- at
		}
	}
}

func (p *pinger) ping(ctx context.Context, dst netip.Addr, timeout time.Duration) (time.Duration, bool) {
	p.mu.Lock()
	p.seq++
	seq := p.seq
	ch := make(chan time.Time, 1)
	p.wait[seq] = ch
	p.mu.Unlock()
	forget := func() {
		p.mu.Lock()
		delete(p.wait, seq)
		p.mu.Unlock()
	}

	// 8 байт данных, как у ping: проба дешёвая и для лимитированного канала.
	b, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{
		ID: p.id, Seq: int(seq), Data: probePayload,
	}}).Marshal(nil)
	start := time.Now()
	if _, err := p.conn.WriteTo(b, &net.IPAddr{IP: dst.AsSlice()}); err != nil {
		forget()
		return 0, false
	}
	p.bytes.Add(uint64(len(b) + ipHeader))
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case at := <-ch:
		return at.Sub(start), true
	case <-timer.C:
	case <-ctx.Done():
	}
	forget()
	return 0, false
}
