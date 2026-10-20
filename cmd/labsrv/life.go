package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// lifeEvent — одно действие устройства. LinkSrv — канал по адресу, с которого
// пришёл к серверу (что на деле); LinkAPI и Class — по мнению ядра
// (/api/connections). Moved — продолжение игры ушло не тем каналом, что
// начало.
type lifeEvent struct {
	T       time.Time `json:"t"`
	Device  string    `json:"device,omitempty"`
	Kind    string    `json:"kind"`
	Expect  string    `json:"expect,omitempty"`
	Class   string    `json:"class,omitempty"`
	LinkAPI string    `json:"link_api,omitempty"`
	LinkSrv string    `json:"link_srv,omitempty"`
	First   string    `json:"first_link,omitempty"`
	Moved   bool      `json:"moved,omitempty"`
	OK      bool      `json:"ok"`
	Err     string    `json:"err,omitempty"`
	Ms      int64     `json:"ms"`
	// Links — состояние каналов (снимок раз в 30 с).
	Links map[string]string `json:"links,omitempty"`
}

type lifeSession struct {
	conn  *net.UDPConn
	first string
}

type lifeRun struct {
	server, bcast netip.Addr
	api, dns      string
	timeout       time.Duration
	games         map[string]*lifeSession
}

// linkOf — канал стенда по адресу источника: 100.64.<номер>.2.
func linkOf(src string) string {
	switch src {
	case "100.64.1.2":
		return "isp1"
	case "100.64.2.2":
		return "isp2"
	case "100.64.3.2":
		return "lte"
	}
	return src
}

// life — «жизнь дома» на стенде: устройства по расписанию открывают новые
// соединения разных видов (и продолжают игры), JSON-строка на событие.
func life(args []string) error {
	fs := flag.NewFlagSet("life", flag.ExitOnError)
	duration := fs.Duration("duration", 8*time.Hour, "how long to run")
	every := fs.Duration("every", 2*time.Second, "pause between actions")
	devices := fs.String("devices", "192.168.77.10,192.168.77.11,192.168.77.12,192.168.77.13", "device addresses (must exist on the client)")
	server := fs.String("server", "203.0.113.10", "lab server")
	bcast := fs.String("broadcast", "203.0.113.100", "broadcast ingest address (TCP 89)")
	api := fs.String("api", "http://192.168.77.1:8080", "trossd API")
	dns := fs.String("dns", "192.168.77.1:53", "home DNS")
	out := fs.String("out", "", "append events here (empty — stdout)")
	_ = fs.Parse(args)

	w := io.Writer(os.Stdout)
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	emit := func(e lifeEvent) {
		_ = enc.Encode(e)
		_ = bw.Flush()
	}
	r := &lifeRun{server: netip.MustParseAddr(*server), bcast: netip.MustParseAddr(*bcast), api: *api, dns: *dns,
		timeout: 2 * time.Second, games: map[string]*lifeSession{}}
	devs := strings.Split(*devices, ",")
	type kind struct {
		name   string
		weight int
	}
	kinds := []kind{{"web", 30}, {"download", 15}, {"game_new", 8}, {"game_keep", 17}, {"call", 10}, {"broadcast", 5}, {"dns", 15}}
	total := 0
	for _, k := range kinds {
		total += k.weight
	}
	deadline := time.Now().Add(*duration)
	lastLinks := time.Time{}
	for time.Now().Before(deadline) {
		if time.Since(lastLinks) >= 30*time.Second {
			lastLinks = time.Now()
			emit(lifeEvent{T: time.Now(), Kind: "links", Links: r.links(), OK: true})
		}
		dev := devs[rand.IntN(len(devs))]
		n := rand.IntN(total)
		var k string
		for _, kk := range kinds {
			if n < kk.weight {
				k = kk.name
				break
			}
			n -= kk.weight
		}
		emit(r.act(dev, k))
		time.Sleep(*every)
	}
	for _, s := range r.games {
		s.conn.Close()
	}
	return nil
}

func (r *lifeRun) act(dev, k string) lifeEvent {
	e := lifeEvent{T: time.Now(), Device: dev, Kind: k}
	t0 := time.Now()
	var local, remote netip.AddrPort
	var err error
	switch k {
	case "web":
		e.Expect = "default"
		remote = netip.AddrPortFrom(r.server, 80)
		local, e.LinkSrv, err = r.httpWhoami(dev, remote)
	case "download":
		e.Expect = "bulk"
		remote = netip.AddrPortFrom(r.server, 88)
		local, e.LinkSrv, err = r.httpWhoami(dev, remote)
	case "broadcast":
		e.Expect = "broadcast"
		remote = netip.AddrPortFrom(r.bcast, 89)
		local, e.LinkSrv, err = r.httpWhoami(dev, remote)
	case "call":
		e.Expect = "voip"
		remote = netip.AddrPortFrom(r.server, 9001)
		// STUN: признак звонка (magic cookie в байтах 4–7), затем просьба
		// эхо-сервера назвать адрес.
		msg := make([]byte, 20)
		binary.BigEndian.PutUint16(msg, 0x0001)
		binary.BigEndian.PutUint32(msg[4:], 0x2112a442)
		for i := 8; i < 20; i++ {
			msg[i] = byte(rand.IntN(256))
		}
		local, e.LinkSrv, err = r.udpWhoami(dev, remote, append(msg, []byte("whoami")...), nil)
	case "game_new", "game_keep":
		e.Expect = "gaming"
		remote = netip.AddrPortFrom(r.server, 9000)
		s := r.games[dev]
		if k == "game_new" || s == nil {
			if s != nil {
				s.conn.Close()
			}
			s = &lifeSession{}
			r.games[dev] = s
			e.Kind = "game_new"
		}
		local, e.LinkSrv, err = r.udpWhoami(dev, remote, []byte("whoami"), s)
		if err == nil {
			if s.first == "" {
				s.first = e.LinkSrv
			}
			e.First = s.first
			e.Moved = e.LinkSrv != s.first
		}
	case "dns":
		err = r.dnsQuery(dev)
	}
	e.Ms = time.Since(t0).Milliseconds()
	e.OK = err == nil
	if err != nil {
		e.Err = err.Error()
	}
	if local.IsValid() {
		e.Class, e.LinkAPI = r.kernelView(dev, local, remote)
	}
	return e
}

func (r *lifeRun) httpWhoami(dev string, remote netip.AddrPort) (netip.AddrPort, string, error) {
	d := net.Dialer{Timeout: r.timeout, LocalAddr: &net.TCPAddr{IP: net.ParseIP(dev)}}
	c, err := d.Dial("tcp4", remote.String())
	if err != nil {
		return netip.AddrPort{}, "", err
	}
	defer c.Close()
	local := netip.MustParseAddrPort(c.LocalAddr().String())
	_ = c.SetDeadline(time.Now().Add(r.timeout))
	if _, err := io.WriteString(c, "GET /whoami HTTP/1.0\r\nHost: lab\r\n\r\n"); err != nil {
		return local, "", err
	}
	body, err := io.ReadAll(io.LimitReader(c, 4096))
	if err != nil {
		return local, "", err
	}
	i := strings.LastIndex(string(body), "src=")
	if i < 0 {
		return local, "", errors.New("no src in reply")
	}
	return local, linkOf(strings.TrimSpace(string(body)[i+4:])), nil
}

// udpWhoami — из нового сокета или сессии игры (тот же порт источника).
func (r *lifeRun) udpWhoami(dev string, remote netip.AddrPort, msg []byte, s *lifeSession) (netip.AddrPort, string, error) {
	var c *net.UDPConn
	if s != nil && s.conn != nil {
		c = s.conn
	} else {
		var err error
		c, err = net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(dev)}, net.UDPAddrFromAddrPort(remote))
		if err != nil {
			return netip.AddrPort{}, "", err
		}
		if s != nil {
			s.conn = c
		} else {
			defer c.Close()
		}
	}
	local := netip.MustParseAddrPort(c.LocalAddr().String())
	_ = c.SetDeadline(time.Now().Add(r.timeout))
	if _, err := c.Write(msg); err != nil {
		return local, "", err
	}
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil {
		return local, "", err
	}
	reply := strings.TrimSpace(string(buf[:n]))
	if !strings.HasPrefix(reply, "src=") {
		return local, "", fmt.Errorf("unexpected reply %q", reply)
	}
	return local, linkOf(reply[4:]), nil
}

func (r *lifeRun) dnsQuery(dev string) error {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: uint16(rand.IntN(65536)), RecursionDesired: true})
	_ = b.StartQuestions()
	name := fmt.Sprintf("life-%d.example.", rand.IntN(1000))
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	c, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(dev)}, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(r.dns)))
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(r.timeout))
	if _, err := c.Write(q); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return err
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:n]); err != nil {
		return err
	}
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) == 0 {
		return fmt.Errorf("dns %v, %d answers", m.RCode, len(m.Answers))
	}
	return nil
}

// kernelView — класс и канал соединения по снимку conntrack демона.
func (r *lifeRun) kernelView(dev string, local, remote netip.AddrPort) (string, string) {
	c := http.Client{Timeout: r.timeout}
	resp, err := c.Get(r.api + "/api/connections?limit=5000&device=" + dev)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	var v struct {
		Connections []struct {
			Src   netip.AddrPort `json:"src"`
			Dst   netip.AddrPort `json:"dst"`
			Link  string         `json:"link"`
			Class string         `json:"class"`
		} `json:"connections"`
	}
	if json.NewDecoder(resp.Body).Decode(&v) != nil {
		return "", ""
	}
	for _, cn := range v.Connections {
		if cn.Src == local && cn.Dst == remote {
			return cn.Class, cn.Link
		}
	}
	return "", ""
}

func (r *lifeRun) links() map[string]string {
	c := http.Client{Timeout: r.timeout}
	resp, err := c.Get(r.api + "/api/links")
	if err != nil {
		return map[string]string{"error": err.Error()}
	}
	defer resp.Body.Close()
	var v struct {
		Links []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"links"`
	}
	if json.NewDecoder(resp.Body).Decode(&v) != nil {
		return nil
	}
	out := map[string]string{}
	for _, l := range v.Links {
		out[l.ID] = l.State
	}
	return out
}
