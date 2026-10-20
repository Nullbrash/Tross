package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// upnpc — программа устройства просит проброс, как торрент-клиент или
// приставка: UPnP IGD (поиск по SSDP, описание, SOAP), NAT-PMP или PCP.
//
//	labsrv upnpc -igd -proto tcp -port 45000 -lease 0 -desc TorrentClient [-delete]
//	labsrv upnpc -natpmp -gw 192.168.77.1 -proto udp -port 46000 -lease 3600
//	labsrv upnpc -pcp -gw 192.168.77.1 -proto tcp -port 47000 -lease 3600
//
// Печатает «ok [внешний порт срок]» или код ошибки протокола.
func upnpc(args []string) error {
	fs := flag.NewFlagSet("upnpc", flag.ExitOnError)
	igd := fs.Bool("igd", false, "UPnP IGD")
	pmp := fs.Bool("natpmp", false, "NAT-PMP")
	pcp := fs.Bool("pcp", false, "PCP")
	gw := fs.String("gw", "", "gateway (NAT-PMP, PCP)")
	proto := fs.String("proto", "tcp", "tcp | udp")
	port := fs.Uint("port", 0, "internal (and external) port")
	lease := fs.Uint("lease", 3600, "seconds; 0 — permanent (IGD) or delete (NAT-PMP, PCP)")
	desc := fs.String("desc", "labsrv", "IGD description")
	del := fs.Bool("delete", false, "IGD: delete the mapping")
	_ = fs.Parse(args)
	switch {
	case *igd:
		return igdClient(*proto, uint16(*port), uint32(*lease), *desc, *del)
	case *pmp || *pcp:
		g, err := netip.ParseAddr(*gw)
		if err != nil {
			return fmt.Errorf("upnpc: -gw: %v", err)
		}
		if *pmp {
			return natpmpClient(g, *proto, uint16(*port), uint32(*lease))
		}
		return pcpClient(g, *proto, uint16(*port), uint32(*lease))
	}
	return errors.New("upnpc: want -igd, -natpmp or -pcp")
}

func igdClient(proto string, port uint16, lease uint32, desc string, del bool) error {
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return err
	}
	defer c.Close()
	q := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
	// Как настоящие клиенты — запрос дважды (UDP может потеряться).
	for range 2 {
		if _, err := c.WriteToUDP([]byte(q), &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}); err != nil {
			return err
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return fmt.Errorf("upnpc: no SSDP reply: %w", err)
	}
	loc := regexp.MustCompile(`(?im)^LOCATION:\s*(\S+)`).FindSubmatch(buf[:n])
	if loc == nil {
		return fmt.Errorf("upnpc: no LOCATION in %q", buf[:n])
	}
	resp, err := http.Get(string(loc[1]))
	if err != nil {
		return err
	}
	desc0, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	ctl := regexp.MustCompile(`WANIPConnection:1</serviceType>.*?<controlURL>([^<]+)</controlURL>`).FindSubmatch(desc0)
	if ctl == nil {
		return errors.New("upnpc: no WANIPConnection in the description")
	}
	u := strings.TrimSuffix(string(loc[1]), "/rootDesc.xml") + string(ctl[1])
	// Свой адрес — тот, с которого виден шлюз.
	host := strings.Split(strings.TrimPrefix(string(loc[1]), "http://"), "/")[0]
	conn, err := net.Dial("udp4", host)
	if err != nil {
		return err
	}
	self := conn.LocalAddr().(*net.UDPAddr).IP.String()
	conn.Close()
	action := "AddPortMapping"
	argv := fmt.Sprintf("<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>%s</NewProtocol><NewInternalPort>%d</NewInternalPort>"+
		"<NewInternalClient>%s</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>%s</NewPortMappingDescription><NewLeaseDuration>%d</NewLeaseDuration>",
		port, strings.ToUpper(proto), port, self, desc, lease)
	if del {
		action = "DeletePortMapping"
		argv = fmt.Sprintf("<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>%s</NewProtocol>", port, strings.ToUpper(proto))
	}
	body := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>` +
		`<u:` + action + ` xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">` + argv + `</u:` + action + `></s:Body></s:Envelope>`
	req, _ := http.NewRequest("POST", u, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPACTION", `"urn:schemas-upnp-org:service:WANIPConnection:1#`+action+`"`)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if code := regexp.MustCompile(`<errorCode>(\d+)</errorCode>`).FindSubmatch(out); code != nil {
		fmt.Printf("error %s\n", code[1])
		return nil
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("upnpc: %s %s", resp.Status, out)
	}
	fmt.Println("ok")
	return nil
}

func udpExchange(gw netip.Addr, req []byte) ([]byte, error) {
	c, err := net.Dial("udp4", netip.AddrPortFrom(gw, 5351).String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, 1100)
	n, err := c.Read(buf)
	return buf[:n], err
}

func natpmpClient(gw netip.Addr, proto string, port uint16, lease uint32) error {
	b := make([]byte, 12)
	b[1] = 1
	if proto == "tcp" {
		b[1] = 2
	}
	binary.BigEndian.PutUint16(b[4:6], port)
	binary.BigEndian.PutUint16(b[6:8], port)
	binary.BigEndian.PutUint32(b[8:12], lease)
	r, err := udpExchange(gw, b)
	if err != nil {
		return err
	}
	if len(r) < 16 {
		return fmt.Errorf("upnpc: short NAT-PMP reply %x", r)
	}
	if res := binary.BigEndian.Uint16(r[2:4]); res != 0 {
		fmt.Printf("result %d\n", res)
		return nil
	}
	fmt.Printf("ok %d %d\n", binary.BigEndian.Uint16(r[10:12]), binary.BigEndian.Uint32(r[12:16]))
	return nil
}

func pcpClient(gw netip.Addr, proto string, port uint16, lease uint32) error {
	c, err := net.Dial("udp4", netip.AddrPortFrom(gw, 5351).String())
	if err != nil {
		return err
	}
	self := netip.MustParseAddr(c.LocalAddr().(*net.UDPAddr).IP.String())
	c.Close()
	b := make([]byte, 60)
	b[0], b[1] = 2, 1
	binary.BigEndian.PutUint32(b[4:8], lease)
	s := self.As16()
	copy(b[8:24], s[:])
	copy(b[24:36], "labsrv-nonce")
	b[36] = 17
	if proto == "tcp" {
		b[36] = 6
	}
	binary.BigEndian.PutUint16(b[40:42], port)
	binary.BigEndian.PutUint16(b[42:44], port)
	r, err := udpExchange(gw, b)
	if err != nil {
		return err
	}
	if len(r) < 60 {
		return fmt.Errorf("upnpc: short PCP reply %x", r)
	}
	if r[3] != 0 {
		fmt.Printf("result %d\n", r[3])
		return nil
	}
	fmt.Printf("ok %d %d\n", binary.BigEndian.Uint16(r[42:44]), binary.BigEndian.Uint32(r[4:8]))
	return nil
}
