package procfs

import (
	"math"
	"testing"
)

const statA = `cpu  100 0 50 800 10 5 20 0 0 0
cpu0 50 0 25 400 5 2 10 0 0 0
intr 12345
`

const statB = `cpu  130 10 70 960 10 5 40 0 0 0
cpu0 65 5 35 480 5 2 20 0 0 0
`

func TestCPUDelta(t *testing.T) {
	a, err := ParseCPU(statA)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := ParseCPU(statB)
	s := CPUDelta(a, b)
	// Приращение: user+nice 40, system 20, idle 160, softirq 20 → всего 240.
	near := func(got, want float64) bool { return math.Abs(got-want) < 1e-9 }
	if !near(s.User, 40.0*100/240) || !near(s.SoftIRQ, 20.0*100/240) || !near(s.Idle, 160.0*100/240) {
		t.Fatalf("delta = %+v", s)
	}
	if z := CPUDelta(a, a); z.Idle != 100 {
		t.Fatalf("zero interval must report idle, got %+v", z)
	}
}

func TestParseMeminfo(t *testing.T) {
	m, err := ParseMeminfo("MemTotal:        3435520 kB\nMemFree: 1 kB\nMemAvailable:    3024000 kB\nSwapTotal: 1855484 kB\nSwapFree: 1855000 kB\n")
	if err != nil {
		t.Fatal(err)
	}
	if m.TotalKB != 3435520 || m.AvailableKB != 3024000 || m.SwapUsedKB != 484 {
		t.Fatalf("mem = %+v", m)
	}
	if _, err := ParseMeminfo("MemTotal: 1 kB\n"); err == nil {
		t.Fatal("missing MemAvailable must fail")
	}
}

func TestParseDisk(t *testing.T) {
	ds := `   8       0 sda 4425 1203 258998 1500 1712 3204 29360 4200 0 3500 5700 0 0 0 0
   8       6 sda6 4000 1100 250000 1400 1700 3200 29300 4100 0 3400 5500 0 0 0 0
`
	n, err := ParseDiskSectorsWritten(ds, "sda")
	if err != nil || n != 29360 {
		t.Fatalf("sda written = %d, %v", n, err)
	}
	if _, err := ParseDiskSectorsWritten(ds, "nvme0n1"); err == nil {
		t.Fatal("unknown device must fail")
	}
}

func TestParseProcStat(t *testing.T) {
	// Имя со скобкой и пробелом — классическая ловушка разбора.
	stat := "1234 (weird) name) S 1 1234 1234 0 -1 4194560 100 0 0 0 250 75 0 0 20 0 8 0 500 10000 300"
	u, s, err := ParseProcStat(stat)
	if err != nil || u != 250 || s != 75 {
		t.Fatalf("utime/stime = %d/%d, %v", u, s, err)
	}
	rss, err := ParseVmRSS("Name:\ttrossd\nVmPeak:\t 9000 kB\nVmRSS:\t   15432 kB\n")
	if err != nil || rss != 15432 {
		t.Fatalf("rss = %d, %v", rss, err)
	}
}

func TestParseIOWriteBytes(t *testing.T) {
	io := "rchar: 100\nwchar: 200\nread_bytes: 4096\nwrite_bytes: 81920\ncancelled_write_bytes: 0\n"
	if n, err := ParseIOWriteBytes(io); err != nil || n != 81920 {
		t.Fatalf("write_bytes = %d, %v", n, err)
	}
	if _, err := ParseIOWriteBytes("rchar: 1\n"); err == nil {
		t.Fatal("missing field must be an error")
	}
}
