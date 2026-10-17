package lists

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"tross/core/model"
)

// LinkDialer — сокет через канал (resolver.LinkDialer).
type LinkDialer func(link model.LinkID) *net.Dialer

// HTTPFetcher — загрузка через проводные каналы по очереди: links отдаёт
// пригодные неплатные каналы по приоритету (большие списки через LTE не
// качаются — квота). Имена хостов спрашиваются у своего резолвера (dns):
// системный DNS мини-ПК — это он же, а запасной — следом.
func HTTPFetcher(links func() []model.LinkID, dial LinkDialer, dns []string, timeout time.Duration) Fetcher {
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		var errs []error
		for _, a := range dns {
			c, err := d.DialContext(ctx, network, a)
			if err == nil {
				return c, nil
			}
			errs = append(errs, err)
		}
		return nil, errors.Join(errs...)
	}}
	var mu sync.Mutex
	clients := map[model.LinkID]*http.Client{}
	client := func(l model.LinkID) *http.Client {
		mu.Lock()
		defer mu.Unlock()
		if c := clients[l]; c != nil {
			return c
		}
		d := dial(l)
		d.Resolver = resolver
		c := &http.Client{Timeout: timeout, Transport: &http.Transport{
			DialContext: d.DialContext, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 30 * time.Second,
		}}
		clients[l] = c
		return c
	}
	return func(ctx context.Context, url, etag string) (Fetched, error) {
		ls := links()
		if len(ls) == 0 {
			return Fetched{}, errors.New("no usable unmetered link")
		}
		var errs []error
		for _, l := range ls {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return Fetched{}, err
			}
			if etag != "" {
				req.Header.Set("If-None-Match", etag)
			}
			resp, err := client(l).Do(req)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", l, err))
				continue
			}
			switch resp.StatusCode {
			case http.StatusNotModified:
				resp.Body.Close()
				return Fetched{NotModified: true, ETag: etag}, nil
			case http.StatusOK:
				return Fetched{Body: resp.Body, ETag: resp.Header.Get("ETag")}, nil
			}
			resp.Body.Close()
			// Ответ сервера — не беда канала: другим каналом не повторяем.
			return Fetched{}, fmt.Errorf("http %d", resp.StatusCode)
		}
		return Fetched{}, errors.Join(errs...)
	}
}
