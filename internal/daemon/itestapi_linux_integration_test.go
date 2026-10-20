//go:build linux && integration

package daemon

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// itest — сессия API демона текущего теста (startDaemon, служба systemd).
var itest *apiSession

// apiPath — путь из полного адреса (тесты пишут "http://<listen>/api/…").
func apiPath(url string) string {
	if i := strings.Index(url, "/api/"); i >= 0 {
		return url[i:]
	}
	return url
}

// apiBytes — тело ответа; не 200 — ошибка с телом.
func apiBytes(method, url string, body []byte) ([]byte, error) {
	resp, err := itest.do(method, apiPath(url), body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return b, fmt.Errorf("%s %s: %s %s", method, apiPath(url), resp.Status, b)
	}
	return b, nil
}
