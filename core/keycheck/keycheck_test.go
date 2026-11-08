package keycheck

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseKeepsSecretsOutOfSerializedRecord(t *testing.T) {
	records, invalid := Parse([]string{
		"https://subscription.example/path",
		"vless://private-value@example:443",
		"vless://private-value@example:443",
		"unsupported-value",
	})
	if len(records) != 2 || records[0].ID == "" || records[1].ID == "" {
		t.Fatalf("records = %#v", records)
	}
	if len(invalid) != 1 || invalid[0].Reason != "unsupported_format" {
		t.Fatalf("invalid = %#v", invalid)
	}
	if records[1].Kind != Outbound {
		t.Fatalf("kind = %q", records[1].Kind)
	}
}

func TestWriteOutputsSeparatesResultAndKeepsSecretOutOfSummary(t *testing.T) {
	dir := t.TempDir()
	secret := "vless://private-value@example:443"
	records := []Record{{ID: "a", Raw: secret}, {ID: "b", Raw: "vless://second"}, {ID: "c", Raw: "vless://third"}}
	results := []Result{{RecordID: "a", Status: "working"}, {RecordID: "b", Status: "not_working"}, {RecordID: "c", Status: "inconclusive"}}
	if err := WriteOutputs(dir, records, results); err != nil {
		t.Fatal(err)
	}
	working, err := os.ReadFile(filepath.Join(dir, "working.txt"))
	if err != nil || string(working) != "a\t"+secret+"\n" {
		t.Fatalf("working = %q, %v", working, err)
	}
	unresolved, err := os.ReadFile(filepath.Join(dir, "unresolved.txt"))
	if err != nil || string(unresolved) != "c\tvless://third\n" {
		t.Fatalf("unresolved = %q, %v", unresolved, err)
	}
	summary, err := os.ReadFile(filepath.Join(dir, "summary.json"))
	if err != nil || strings.Contains(string(summary), secret) {
		t.Fatalf("summary leaked a secret: %q, %v", summary, err)
	}
}

func TestCheckpointDoesNotRepeatStartedOrCompletedRecords(t *testing.T) {
	dir := t.TempDir()
	checkpoint, err := LoadCheckpoint(dir)
	if err != nil {
		t.Fatal(err)
	}
	started := Record{ID: "started", Kind: Outbound, Raw: "secret-a"}
	completed := Record{ID: "completed", Kind: Outbound, Raw: "secret-b"}
	pending := Record{ID: "pending", Kind: Outbound, Raw: "secret-c"}
	checkpoint.MarkStarted(started)
	checkpoint.MarkStarted(completed)
	checkpoint.MarkCompleted(Result{RecordID: completed.ID, Status: "working"})
	if err := checkpoint.Save(dir); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadCheckpoint(dir)
	if err != nil {
		t.Fatal(err)
	}
	remaining := reloaded.Pending([]Record{started, completed, pending})
	if len(remaining) != 1 || remaining[0].ID != pending.ID {
		t.Fatalf("pending = %#v", remaining)
	}
}

type selectorFunc func(Record, Target) Route

func (f selectorFunc) Route(record Record, target Target) Route { return f(record, target) }

type fakeProber struct {
	mu      sync.Mutex
	active  int
	maximum int
	calls   map[string]int
	result  ProbeResult
}

func (p *fakeProber) Probe(_ context.Context, record Record, target Target) ProbeResult {
	p.mu.Lock()
	p.active++
	if p.active > p.maximum {
		p.maximum = p.active
	}
	p.calls[record.ID+":"+target.Name]++
	p.mu.Unlock()
	time.Sleep(time.Millisecond)
	p.mu.Lock()
	p.active--
	p.mu.Unlock()
	return p.result
}

func TestRunnerCapsWorkersAndRequiresAllTargetsForWorking(t *testing.T) {
	records := make([]Record, 15)
	for i := range records {
		records[i] = Record{ID: string(rune('a' + i)), Raw: "secret"}
	}
	prober := &fakeProber{calls: make(map[string]int), result: ProbeResult{Status: Reachable}}
	runner := Runner{
		Workers: 99, Timeout: time.Second,
		Targets:  []Target{{Name: "first"}, {Name: "second"}},
		Selector: selectorFunc(func(Record, Target) Route { return RouteProxy }),
		Prober:   prober,
	}
	results, err := runner.Run(context.Background(), records)
	if err != nil || len(results) != len(records) {
		t.Fatalf("Run() = %d results, %v", len(results), err)
	}
	if prober.maximum > MaxWorkers {
		t.Fatalf("maximum workers = %d", prober.maximum)
	}
	for _, result := range results {
		if result.Status != "working" || len(result.Attempts) != 2 {
			t.Fatalf("result = %#v", result)
		}
	}
}

func TestRunnerTriesOnlyProxyTargetsAndKeepsAllInconclusive(t *testing.T) {
	record := Record{ID: "id", Raw: "secret"}
	prober := &fakeProber{calls: make(map[string]int), result: ProbeResult{Status: Inconclusive, Reason: "timeout"}}
	runner := Runner{
		Workers: 1, Timeout: time.Second,
		Targets: []Target{{Name: "direct"}, {Name: "one"}, {Name: "two"}, {Name: "three"}, {Name: "four"}},
		Selector: selectorFunc(func(_ Record, target Target) Route {
			if target.Name == "direct" {
				return RouteDirect
			}
			return RouteProxy
		}),
		Prober: prober,
	}
	results, err := runner.Run(context.Background(), []Record{record})
	if err != nil {
		t.Fatal(err)
	}
	if len(results[0].Attempts) != 5 || results[0].Status != "unresolved" {
		t.Fatalf("result = %#v", results[0])
	}
	if len(prober.calls) != 4 {
		t.Fatalf("calls = %#v", prober.calls)
	}
}

func TestRunCheckpointedSkipsPreviouslyStartedRecords(t *testing.T) {
	dir := t.TempDir()
	checkpoint, err := LoadCheckpoint(dir)
	if err != nil {
		t.Fatal(err)
	}
	previous := Record{ID: "previous", Kind: Outbound, Raw: "secret-a"}
	current := Record{ID: "current", Kind: Outbound, Raw: "secret-b"}
	checkpoint.MarkStarted(previous)
	if err := checkpoint.Save(dir); err != nil {
		t.Fatal(err)
	}
	prober := &fakeProber{calls: make(map[string]int), result: ProbeResult{Status: Reachable}}
	runner := Runner{Workers: 1, Timeout: time.Second, Targets: []Target{{Name: "target"}}, Selector: selectorFunc(func(Record, Target) Route { return RouteProxy }), Prober: prober}
	results, err := runner.RunCheckpointed(context.Background(), checkpoint, dir, []Record{previous, current})
	if err != nil || len(results) != 1 || results[0].RecordID != current.ID {
		t.Fatalf("results = %#v, %v", results, err)
	}
	if prober.calls[previous.ID+":target"] != 0 || prober.calls[current.ID+":target"] != 1 {
		t.Fatalf("calls = %#v", prober.calls)
	}
	reloaded, err := LoadCheckpoint(dir)
	if err != nil || reloaded.Results[current.ID].Status != "working" {
		t.Fatalf("saved state = %#v, %v", reloaded.Results, err)
	}
}
