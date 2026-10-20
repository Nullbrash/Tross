package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/net/websocket"
)

// wsclient — «открытая вкладка интерфейса»: поток /api/ws с cookie сессии,
// переподключение каждые -reconnect; печатает, сколько сообщений пришло.
//
//	labsrv wsclient -url wss://192.168.77.1:8080/api/ws -origin https://192.168.77.1:8080 -cookie TOKEN -duration 8h
func wsclient(args []string) error {
	fs := flag.NewFlagSet("wsclient", flag.ExitOnError)
	url := fs.String("url", "", "wss://host:port/api/ws")
	origin := fs.String("origin", "", "https://host:port")
	cookie := fs.String("cookie", "", "tross_session value")
	dur := fs.Duration("duration", time.Hour, "how long")
	reconnect := fs.Duration("reconnect", 10*time.Minute, "reconnect every")
	_ = fs.Parse(args)
	if *url == "" || *origin == "" || *cookie == "" {
		return errors.New("wsclient: want -url, -origin and -cookie")
	}
	deadline := time.Now().Add(*dur)
	for time.Now().Before(deadline) {
		cfg, err := websocket.NewConfig(*url, *origin)
		if err != nil {
			return err
		}
		cfg.TlsConfig = &tls.Config{InsecureSkipVerify: true}
		cfg.Header = http.Header{"Cookie": {"tross_session=" + *cookie}}
		c, err := websocket.DialConfig(cfg)
		if err != nil {
			log.Printf("wsclient: dial: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}
		until := time.Now().Add(min(*reconnect, time.Until(deadline)))
		n, links, events := 0, 0, 0
		for time.Now().Before(until) {
			_ = c.SetReadDeadline(until)
			var m struct{ Type string }
			if err := websocket.JSON.Receive(c, &m); err != nil {
				break
			}
			n++
			switch m.Type {
			case "links":
				links++
			case "event":
				events++
			}
		}
		c.Close()
		fmt.Printf("%s ws: %d messages (%d links, %d events)\n", time.Now().Format(time.TimeOnly), n, links, events)
	}
	return nil
}
