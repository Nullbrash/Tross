//go:build linux

package linkmon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestSpeedStreamRejectsStubPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stub" {
			_, _ = w.Write([]byte("<html>Please log in</html>"))
			return
		}
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		_, _ = w.Write(make([]byte, n))
	}))
	defer srv.Close()

	var total atomic.Int64
	deadline := time.Now().Add(time.Second)
	err := speedStream(context.Background(), srv.Client(), srv.URL+"/stub", deadline, 1<<30, &total)
	if !errors.Is(err, ErrStubResponse) {
		t.Fatalf("stub page: err = %v, want ErrStubResponse", err)
	}

	total.Store(0)
	err = speedStream(context.Background(), srv.Client(), srv.URL+"/data?n=1048576", deadline, 4<<20, &total)
	if err != nil || total.Load() < 4<<20 {
		t.Fatalf("real data: err = %v, total = %d", err, total.Load())
	}
}
