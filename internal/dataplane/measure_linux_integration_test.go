//go:build linux && integration && extra

package dataplane

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMeasureForwarding — замер ЦП пересылки с правилами демона (пакеты по
// MTU), для сравнения с пустым стендом. Дополнительный тест (признак
// сборки extra, `scripts/lab-itest extra`); цифры — в LAB_MEASURE_OUT.
func TestMeasureForwarding(t *testing.T) {
	out := os.Getenv("LAB_MEASURE_OUT")
	if out == "" {
		t.Fatal("set LAB_MEASURE_OUT=<dir> for the measurement output")
	}
	ctx := context.Background()
	s := newSystem(t)
	lab := os.Getenv("LAB_NETNS")
	measureBin := filepath.Join(filepath.Dir(lab), "..", "bin", "labmeasure")
	if o, err := run(t, lab, "offload", "off"); err != nil {
		t.Fatalf("offload off: %v\n%s", err, o)
	}
	t.Cleanup(func() { _, _ = run(t, lab, "offload", "on") })
	if err := s.Setup(ctx, standSpec()); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"down", "up"} {
		m := exec.Command(measureBin, "-out", filepath.Join(out, "dataplane-isp1-"+dir), "-duration", "24s", "-netns", "tl-tross")
		var mout strings.Builder
		m.Stdout = &mout
		if err := m.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		args := "iperf3 -c " + srv + " -t 20 -P 4"
		if dir == "down" {
			args += " -R"
		}
		res, err := inClient(t, args+" | grep -E 'SUM.*receiver'")
		if err != nil {
			t.Fatalf("iperf3 %s: %v\n%s", dir, err, res)
		}
		_ = m.Wait()
		t.Logf("measure %s: %s", dir, strings.TrimSpace(res))
		for line := range strings.Lines(mout.String()) {
			if strings.HasPrefix(line, "cpu") || strings.HasPrefix(line, "temp") {
				t.Logf("measure %s: %s", dir, strings.TrimSpace(line))
			}
		}
	}
}
