package dataplane

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tross/core/model"
)

func TestFakeRecordsOps(t *testing.T) {
	ctx := context.Background()
	f := NewFake(slog.New(slog.NewTextHandler(io.Discard, nil)))
	spec := Spec{
		LANInterface: "br0",
		Links:        []LinkSpec{{Link: model.Link{ID: "isp1", Interface: "eth1"}, Table: 101, FwMark: 0x100}},
	}
	_ = f.Setup(ctx, spec)
	_ = f.AddToSet(ctx, SetDPI, netip.MustParseAddr("203.0.113.1"), time.Minute)
	_ = f.Teardown(ctx)

	ops := f.Ops()
	if len(ops) != 4 {
		t.Fatalf("ops = %q", ops)
	}
	if !strings.Contains(ops[0], "table=101") || !strings.Contains(ops[0], "mark=0x100") {
		t.Errorf("link op = %q", ops[0])
	}
	if ops[3] != "teardown" {
		t.Errorf("last op = %q, want teardown", ops[3])
	}
}
