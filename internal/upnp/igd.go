package upnp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"tross/core/model"
	coreupnp "tross/core/upnp"
)

const (
	typeIGD    = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
	typeWAN    = "urn:schemas-upnp-org:device:WANDevice:1"
	typeWANCon = "urn:schemas-upnp-org:device:WANConnectionDevice:1"
	svcIPConn  = "urn:schemas-upnp-org:service:WANIPConnection:1"
	svcCommon  = "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"
)

// IGD — описание шлюза и управление пробросами (UPnP IGD v1) на адресе LAN.
type IGD struct {
	m     Mapper
	lan   netip.AddrPort
	inLAN func(netip.Addr) bool
	log   *slog.Logger
	uuid  string
}

func NewIGD(m Mapper, lan netip.AddrPort, inLAN func(netip.Addr) bool, log *slog.Logger) *IGD {
	h := sha256.Sum256([]byte("tross-igd/" + lan.Addr().String()))
	u := fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
	return &IGD{m: m, lan: lan, inLAN: inLAN, log: log, uuid: u}
}

func (g *IGD) location() string { return "http://" + g.lan.String() + "/rootDesc.xml" }

func (g *IGD) rootDesc() string {
	svc := func(typ, id, name string) string {
		return fmt.Sprintf("<service><serviceType>%s</serviceType><serviceId>urn:upnp-org:serviceId:%s</serviceId>"+
			"<SCPDURL>/%s.xml</SCPDURL><controlURL>/ctl/%s</controlURL><eventSubURL>/evt/%s</eventSubURL></service>", typ, id, name, name, name)
	}
	dev := func(typ, name string, n int, inner string) string {
		return fmt.Sprintf("<device><deviceType>%s</deviceType><friendlyName>%s</friendlyName><manufacturer>Tross</manufacturer>"+
			"<manufacturerURL>https://github.com/Nullbrash/Tross</manufacturerURL><modelName>Tross</modelName><UDN>uuid:%s-%d</UDN>%s</device>", typ, name, g.uuid, n, inner)
	}
	con := dev(typeWANCon, "Tross WAN connection", 2, "<serviceList>"+svc(svcIPConn, "WANIPConn1", "WANIPCn")+"</serviceList>")
	wan := dev(typeWAN, "Tross WAN", 1, "<serviceList>"+svc(svcCommon, "WANCommonIFC1", "WANCfg")+"</serviceList><deviceList>"+con+"</deviceList>")
	root := dev(typeIGD, "Tross", 0, "<deviceList>"+wan+"</deviceList>")
	return `<?xml version="1.0"?>` + "\n" + `<root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion>` + root + "</root>\n"
}

type arg struct{ name, dir, variable string }

type action struct {
	name string
	args []arg
}

var ipConnActions = []action{
	{"GetExternalIPAddress", []arg{{"NewExternalIPAddress", "out", "ExternalIPAddress"}}},
	{"GetStatusInfo", []arg{{"NewConnectionStatus", "out", "ConnectionStatus"}, {"NewLastConnectionError", "out", "LastConnectionError"}, {"NewUptime", "out", "Uptime"}}},
	{"GetConnectionTypeInfo", []arg{{"NewConnectionType", "out", "ConnectionType"}, {"NewPossibleConnectionTypes", "out", "PossibleConnectionTypes"}}},
	{"GetNATRSIPStatus", []arg{{"NewRSIPAvailable", "out", "RSIPAvailable"}, {"NewNATEnabled", "out", "NATEnabled"}}},
	{"AddPortMapping", []arg{{"NewRemoteHost", "in", "RemoteHost"}, {"NewExternalPort", "in", "ExternalPort"}, {"NewProtocol", "in", "PortMappingProtocol"},
		{"NewInternalPort", "in", "InternalPort"}, {"NewInternalClient", "in", "InternalClient"}, {"NewEnabled", "in", "PortMappingEnabled"},
		{"NewPortMappingDescription", "in", "PortMappingDescription"}, {"NewLeaseDuration", "in", "PortMappingLeaseDuration"}}},
	{"DeletePortMapping", []arg{{"NewRemoteHost", "in", "RemoteHost"}, {"NewExternalPort", "in", "ExternalPort"}, {"NewProtocol", "in", "PortMappingProtocol"}}},
	{"GetSpecificPortMappingEntry", []arg{{"NewRemoteHost", "in", "RemoteHost"}, {"NewExternalPort", "in", "ExternalPort"}, {"NewProtocol", "in", "PortMappingProtocol"},
		{"NewInternalPort", "out", "InternalPort"}, {"NewInternalClient", "out", "InternalClient"}, {"NewEnabled", "out", "PortMappingEnabled"},
		{"NewPortMappingDescription", "out", "PortMappingDescription"}, {"NewLeaseDuration", "out", "PortMappingLeaseDuration"}}},
	{"GetGenericPortMappingEntry", []arg{{"NewPortMappingIndex", "in", "PortMappingNumberOfEntries"}, {"NewRemoteHost", "out", "RemoteHost"},
		{"NewExternalPort", "out", "ExternalPort"}, {"NewProtocol", "out", "PortMappingProtocol"}, {"NewInternalPort", "out", "InternalPort"},
		{"NewInternalClient", "out", "InternalClient"}, {"NewEnabled", "out", "PortMappingEnabled"}, {"NewPortMappingDescription", "out", "PortMappingDescription"},
		{"NewLeaseDuration", "out", "PortMappingLeaseDuration"}}},
}

var commonActions = []action{
	{"GetCommonLinkProperties", []arg{{"NewWANAccessType", "out", "WANAccessType"}, {"NewLayer1UpstreamMaxBitRate", "out", "Layer1UpstreamMaxBitRate"},
		{"NewLayer1DownstreamMaxBitRate", "out", "Layer1DownstreamMaxBitRate"}, {"NewPhysicalLinkStatus", "out", "PhysicalLinkStatus"}}},
	{"GetTotalBytesSent", []arg{{"NewTotalBytesSent", "out", "TotalBytesSent"}}},
	{"GetTotalBytesReceived", []arg{{"NewTotalBytesReceived", "out", "TotalBytesReceived"}}},
}

var variableTypes = map[string]string{
	"ExternalPort": "ui2", "InternalPort": "ui2", "PortMappingLeaseDuration": "ui4", "PortMappingNumberOfEntries": "ui2",
	"PortMappingEnabled": "boolean", "RSIPAvailable": "boolean", "NATEnabled": "boolean", "Uptime": "ui4",
	"Layer1UpstreamMaxBitRate": "ui4", "Layer1DownstreamMaxBitRate": "ui4", "TotalBytesSent": "ui4", "TotalBytesReceived": "ui4",
}

func scpd(actions []action) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>` + "\n" + `<scpd xmlns="urn:schemas-upnp-org:service-1-0"><specVersion><major>1</major><minor>0</minor></specVersion><actionList>`)
	vars := map[string]bool{}
	var order []string
	for _, a := range actions {
		fmt.Fprintf(&b, "<action><name>%s</name><argumentList>", a.name)
		for _, x := range a.args {
			fmt.Fprintf(&b, "<argument><name>%s</name><direction>%s</direction><relatedStateVariable>%s</relatedStateVariable></argument>", x.name, x.dir, x.variable)
			if !vars[x.variable] {
				vars[x.variable] = true
				order = append(order, x.variable)
			}
		}
		b.WriteString("</argumentList></action>")
	}
	b.WriteString("</actionList><serviceStateTable>")
	for _, v := range order {
		t := variableTypes[v]
		if t == "" {
			t = "string"
		}
		fmt.Fprintf(&b, `<stateVariable sendEvents="no"><name>%s</name><dataType>%s</dataType></stateVariable>`, v, t)
	}
	b.WriteString("</serviceStateTable></scpd>\n")
	return b.String()
}

// soapFault — ошибка UPnP (код и описание из стандарта IGD).
type soapFault struct {
	code int
	desc string
}

func (f soapFault) Error() string { return fmt.Sprintf("upnp error %d: %s", f.code, f.desc) }

var (
	errInvalidAction  = soapFault{401, "Invalid Action"}
	errInvalidArgs    = soapFault{402, "Invalid Args"}
	errNotAuthorized  = soapFault{606, "Action not authorized"}
	errBadIndex       = soapFault{713, "SpecifiedArrayIndexInvalid"}
	errNoSuchEntry    = soapFault{714, "NoSuchEntryInArray"}
	errWildcardPort   = soapFault{716, "WildCardNotPermittedInExtPort"}
	errConflict       = soapFault{718, "ConflictInMappingEntry"}
	errRemoteHostOnly = soapFault{726, "RemoteHostOnlySupportsWildcard"}
	errNoPortMaps     = soapFault{728, "NoPortMapsAvailable"}
	errActionFailed   = soapFault{501, "Action Failed"}
)

// parseSOAP — имя действия и его аргументы из тела запроса.
func parseSOAP(body []byte) (string, map[string]string, error) {
	d := xml.NewDecoder(bytes.NewReader(body))
	var action string
	args := map[string]string{}
	depth, inBody, cur := 0, false, ""
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			switch {
			case !inBody && t.Name.Local == "Body":
				inBody = true
			case inBody && action == "":
				action = t.Name.Local
			case inBody && action != "":
				cur = t.Name.Local
			}
		case xml.CharData:
			if cur != "" && len(args) < 32 {
				args[cur] += string(t)
			}
		case xml.EndElement:
			depth--
			cur = ""
		}
	}
	if action == "" {
		return "", nil, errors.New("no action in the SOAP body")
	}
	for k, v := range args {
		args[k] = strings.TrimSpace(v)
	}
	return action, args, nil
}

func soapReply(svc, action string, out [][2]string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>` + "\n" + `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>`)
	fmt.Fprintf(&b, `<u:%sResponse xmlns:u="%s">`, action, svc)
	for _, kv := range out {
		fmt.Fprintf(&b, "<%s>%s</%s>", kv[0], html.EscapeString(kv[1]), kv[0])
	}
	fmt.Fprintf(&b, "</u:%sResponse></s:Body></s:Envelope>\n", action)
	return b.String()
}

func soapFaultBody(f soapFault) string {
	return `<?xml version="1.0"?>` + "\n" + `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>` +
		`<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0">` +
		fmt.Sprintf("<errorCode>%d</errorCode><errorDescription>%s</errorDescription>", f.code, f.desc) +
		"</UPnPError></detail></s:Fault></s:Body></s:Envelope>\n"
}

// Handler — HTTP описания и управления. Только из LAN.
func (g *IGD) Handler() http.Handler {
	mux := http.NewServeMux()
	xmlDoc := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
			_, _ = io.WriteString(w, body)
		}
	}
	mux.HandleFunc("GET /rootDesc.xml", xmlDoc(g.rootDesc()))
	mux.HandleFunc("GET /WANIPCn.xml", xmlDoc(scpd(ipConnActions)))
	mux.HandleFunc("GET /WANCfg.xml", xmlDoc(scpd(commonActions)))
	mux.HandleFunc("POST /ctl/WANIPCn", g.control(svcIPConn))
	mux.HandleFunc("POST /ctl/WANCfg", g.control(svcCommon))
	// Подписка на события — принимается (так ждут клиенты Windows), события
	// не рассылаются.
	mux.HandleFunc("/evt/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "SUBSCRIBE":
			w.Header().Set("SID", "uuid:"+g.uuid+"-sub")
			w.Header().Set("TIMEOUT", "Second-1800")
		case "UNSUBSCRIBE":
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || !g.inLAN(ap.Addr().Unmap()) {
			// Чужому — без ответа (и до сюда он не дойдёт: закрыт при приёме).
			panic(http.ErrAbortHandler)
		}
		mux.ServeHTTP(w, r)
	})
}

func (g *IGD) control(svc string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		src := netip.MustParseAddrPort(r.RemoteAddr).Addr().Unmap()
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
		write := func(code int, s string) {
			w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
			w.Header().Set("EXT", "")
			w.WriteHeader(code)
			_, _ = io.WriteString(w, s)
		}
		if err != nil {
			write(http.StatusInternalServerError, soapFaultBody(errInvalidArgs))
			return
		}
		name, args, err := parseSOAP(body)
		hdr := strings.Trim(r.Header.Get("SOAPACTION"), `" `)
		if _, a, ok := strings.Cut(hdr, "#"); err != nil || ok && a != name {
			write(http.StatusInternalServerError, soapFaultBody(errInvalidAction))
			return
		}
		out, err := g.do(r.Context(), svc, name, args, src)
		var f soapFault
		switch {
		case errors.As(err, &f):
			write(http.StatusInternalServerError, soapFaultBody(f))
		case err != nil:
			g.log.Warn("upnp: igd action", "action", name, "err", err)
			write(http.StatusInternalServerError, soapFaultBody(errActionFailed))
		default:
			write(http.StatusOK, soapReply(svc, name, out))
		}
	}
}

func protoArg(s string) (model.Protocol, bool) {
	switch strings.ToUpper(s) {
	case "TCP":
		return model.ProtoTCP, true
	case "UDP":
		return model.ProtoUDP, true
	}
	return "", false
}

func portArg(s string) (uint16, bool) {
	n, err := strconv.ParseUint(s, 10, 16)
	return uint16(n), err == nil
}

func faultOf(d coreupnp.Decision) error {
	switch d.Reason {
	case coreupnp.Conflict:
		return errConflict
	case coreupnp.NoResources:
		return errNoPortMaps
	}
	return errNotAuthorized
}

func (g *IGD) do(ctx context.Context, svc, name string, a map[string]string, src netip.Addr) ([][2]string, error) {
	if svc == svcCommon {
		switch name {
		case "GetCommonLinkProperties":
			return [][2]string{{"NewWANAccessType", "Ethernet"}, {"NewLayer1UpstreamMaxBitRate", "1000000000"},
				{"NewLayer1DownstreamMaxBitRate", "1000000000"}, {"NewPhysicalLinkStatus", "Up"}}, nil
		case "GetTotalBytesSent":
			return [][2]string{{"NewTotalBytesSent", "0"}}, nil
		case "GetTotalBytesReceived":
			return [][2]string{{"NewTotalBytesReceived", "0"}}, nil
		}
		return nil, errInvalidAction
	}
	switch name {
	case "GetExternalIPAddress":
		return [][2]string{{"NewExternalIPAddress", g.m.ExternalIP().String()}}, nil
	case "GetStatusInfo":
		return [][2]string{{"NewConnectionStatus", "Connected"}, {"NewLastConnectionError", "ERROR_NONE"}, {"NewUptime", strconv.Itoa(int(g.m.Epoch()))}}, nil
	case "GetConnectionTypeInfo":
		return [][2]string{{"NewConnectionType", "IP_Routed"}, {"NewPossibleConnectionTypes", "IP_Routed"}}, nil
	case "GetNATRSIPStatus":
		return [][2]string{{"NewRSIPAvailable", "0"}, {"NewNATEnabled", "1"}}, nil
	case "AddPortMapping", "AddAnyPortMapping":
		if a["NewRemoteHost"] != "" {
			return nil, errRemoteHostOnly
		}
		ext, ok1 := portArg(a["NewExternalPort"])
		in, ok2 := portArg(a["NewInternalPort"])
		proto, ok3 := protoArg(a["NewProtocol"])
		client, err := netip.ParseAddr(a["NewInternalClient"])
		lease, err2 := strconv.ParseUint(a["NewLeaseDuration"], 10, 32)
		if !ok1 || !ok2 || !ok3 || err != nil || err2 != nil || in == 0 {
			return nil, errInvalidArgs
		}
		if ext == 0 && name == "AddPortMapping" {
			return nil, errWildcardPort
		}
		if a["NewEnabled"] == "0" {
			if err := g.m.Unmap(ctx, src, proto, ext); err != nil && !errors.Is(err, ErrNoSuchEntry) {
				return nil, errNotAuthorized
			}
			return nil, nil
		}
		d, err := g.m.Map(ctx, coreupnp.Request{Via: coreupnp.ViaIGD, Proto: proto, ExtPort: ext, IntPort: in, Client: client.Unmap(), Source: src,
			Lease: time.Duration(lease) * time.Second, Desc: a["NewPortMappingDescription"], AnyPort: name == "AddAnyPortMapping"})
		if err != nil {
			return nil, err
		}
		if d.Outcome != coreupnp.Allow {
			return nil, faultOf(d)
		}
		if name == "AddAnyPortMapping" {
			return [][2]string{{"NewReservedPort", strconv.Itoa(int(d.ExtPort))}}, nil
		}
		return nil, nil
	case "DeletePortMapping":
		ext, ok1 := portArg(a["NewExternalPort"])
		proto, ok2 := protoArg(a["NewProtocol"])
		if !ok1 || !ok2 {
			return nil, errInvalidArgs
		}
		switch err := g.m.Unmap(ctx, src, proto, ext); {
		case errors.Is(err, ErrNoSuchEntry):
			return nil, errNoSuchEntry
		case errors.Is(err, ErrNotAllowed):
			return nil, errNotAuthorized
		case err != nil:
			return nil, err
		}
		return nil, nil
	case "GetSpecificPortMappingEntry", "GetGenericPortMappingEntry":
		own, err := g.m.Owned(ctx, src)
		if err != nil {
			return nil, err
		}
		var i int
		if name == "GetGenericPortMappingEntry" {
			n, err := strconv.Atoi(a["NewPortMappingIndex"])
			if err != nil || n < 0 || n >= len(own) {
				return nil, errBadIndex
			}
			i = n
		} else {
			ext, ok1 := portArg(a["NewExternalPort"])
			proto, ok2 := protoArg(a["NewProtocol"])
			if !ok1 || !ok2 {
				return nil, errInvalidArgs
			}
			i = -1
			for j, m := range own {
				if m.Proto == proto && m.ExtPort == ext {
					i = j
				}
			}
			if i < 0 {
				return nil, errNoSuchEntry
			}
		}
		m := own[i]
		out := [][2]string{{"NewInternalPort", strconv.Itoa(int(m.IntPort))}, {"NewInternalClient", m.Addr.String()}, {"NewEnabled", "1"},
			{"NewPortMappingDescription", m.Desc}, {"NewLeaseDuration", strconv.Itoa(int(m.Expires / time.Second))}}
		if name == "GetGenericPortMappingEntry" {
			out = append([][2]string{{"NewRemoteHost", ""}, {"NewExternalPort", strconv.Itoa(int(m.ExtPort))}, {"NewProtocol", strings.ToUpper(string(m.Proto))}}, out...)
		}
		return out, nil
	}
	return nil, errInvalidAction
}

// ServeHTTP — HTTP IGD на адресе LAN до отмены ctx.
func (g *IGD) ServeHTTP(ctx context.Context) error {
	srv := &http.Server{Handler: g.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10, ErrorLog: slog.NewLogLogger(g.log.Handler(), slog.LevelDebug)}
	ln, err := net.Listen("tcp4", g.lan.String())
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(lanListener{ln, g.inLAN}); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// lanListener — соединения не из LAN закрываются сразу при приёме.
type lanListener struct {
	net.Listener
	inLAN func(netip.Addr) bool
}

func (l lanListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil && l.inLAN(ap.Addr().Unmap()) {
			return c, nil
		}
		c.Close()
	}
}
