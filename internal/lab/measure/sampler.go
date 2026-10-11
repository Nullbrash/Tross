package measure

import (
	"tross/internal/procfs"

	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// clockTicks — USER_HZ; на x86-64 Linux всегда 100.
const clockTicks = 100

// Options — что измерять.
type Options struct {
	Disk    string   // устройство для счётчика записи, например "sda"
	Process string   // имя процесса (comm) для RSS и ЦП; пусто — не измерять
	Netns   []string // сетевые пространства, чьи интерфейсы считать
}

// Snapshot — сырые счётчики одной выборки.
type Snapshot struct {
	At       time.Time
	CPU      procfs.CPUTimes
	Mem      procfs.Mem
	DiskSect uint64
	TempC    float64 // NaN-заменитель: -1, если датчика нет
	ProcPID  int
	Proc     procfs.ProcStat
	Net      map[string][]IfaceBytes // netns → интерфейсы
}

// Row — вычисленная строка system.csv.
type Row struct {
	At                                time.Time
	CPU                               procfs.CPUShare
	MemUsedMB, MemAvailMB, SwapUsedMB float64
	DiskWriteKBps, DiskWrittenMB      float64
	TempC                             float64
	ProcPID                           int
	ProcRSSMB, ProcCPUPct             float64 // ProcCPUPct — % одного ядра, как в top
}

// NetRow — строка net.csv.
type NetRow struct {
	At                   time.Time
	Netns, Iface         string
	RxMbps, TxMbps       float64
	RxTotalMB, TxTotalMB float64
}

func Take(o Options) (Snapshot, error) {
	s := Snapshot{At: time.Now(), TempC: -1}
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return s, err
	}
	if s.CPU, err = procfs.ParseCPU(string(b)); err != nil {
		return s, err
	}
	if b, err = os.ReadFile("/proc/meminfo"); err != nil {
		return s, err
	}
	if s.Mem, err = procfs.ParseMeminfo(string(b)); err != nil {
		return s, err
	}
	if o.Disk != "" {
		if b, err = os.ReadFile("/proc/diskstats"); err != nil {
			return s, err
		}
		if s.DiskSect, err = procfs.ParseDiskSectorsWritten(string(b), o.Disk); err != nil {
			return s, err
		}
	}
	s.TempC = readTemp()
	if o.Process != "" {
		if pid := findPID(o.Process); pid > 0 {
			s.ProcPID = pid
			if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
				s.Proc.UTime, s.Proc.STime, _ = procfs.ParseProcStat(string(b))
			}
			if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
				s.Proc.RSSKB, _ = procfs.ParseVmRSS(string(b))
			}
		}
	}
	if len(o.Netns) > 0 {
		s.Net = make(map[string][]IfaceBytes, len(o.Netns))
		for _, ns := range o.Netns {
			out, err := exec.Command("ip", "-n", ns, "-s", "-j", "link", "show").Output()
			if err != nil {
				continue // пространство могло исчезнуть посреди прогона
			}
			if l, err := ParseIPLinkJSON(out); err == nil {
				s.Net[ns] = l
			}
		}
	}
	return s, nil
}

// Diff считает строку по двум выборкам; start — первая выборка прогона.
func Diff(start, prev, cur Snapshot) (Row, []NetRow) {
	dt := cur.At.Sub(prev.At).Seconds()
	if dt <= 0 {
		dt = 1
	}
	r := Row{
		At:            cur.At,
		CPU:           procfs.CPUDelta(prev.CPU, cur.CPU),
		MemUsedMB:     float64(cur.Mem.TotalKB-cur.Mem.AvailableKB) / 1024,
		MemAvailMB:    float64(cur.Mem.AvailableKB) / 1024,
		SwapUsedMB:    float64(cur.Mem.SwapUsedKB) / 1024,
		DiskWriteKBps: float64(cur.DiskSect-prev.DiskSect) * 512 / 1024 / dt,
		DiskWrittenMB: float64(cur.DiskSect-start.DiskSect) * 512 / 1024 / 1024,
		TempC:         cur.TempC,
		ProcPID:       cur.ProcPID,
	}
	if cur.ProcPID != 0 && cur.ProcPID == prev.ProcPID {
		ticks := (cur.Proc.UTime + cur.Proc.STime) - (prev.Proc.UTime + prev.Proc.STime)
		r.ProcCPUPct = float64(ticks) / clockTicks / dt * 100
		r.ProcRSSMB = float64(cur.Proc.RSSKB) / 1024
	} else if cur.ProcPID != 0 {
		r.ProcRSSMB = float64(cur.Proc.RSSKB) / 1024
	}

	var nets []NetRow
	for ns, ifs := range cur.Net {
		for _, i := range ifs {
			p, ok1 := find(prev.Net[ns], i.Name)
			s0, ok2 := find(start.Net[ns], i.Name)
			if !ok1 || !ok2 {
				continue
			}
			nets = append(nets, NetRow{
				At: cur.At, Netns: ns, Iface: i.Name,
				RxMbps:    float64(i.RxBytes-p.RxBytes) * 8 / 1e6 / dt,
				TxMbps:    float64(i.TxBytes-p.TxBytes) * 8 / 1e6 / dt,
				RxTotalMB: float64(i.RxBytes-s0.RxBytes) / 1e6,
				TxTotalMB: float64(i.TxBytes-s0.TxBytes) / 1e6,
			})
		}
	}
	return r, nets
}

func find(l []IfaceBytes, name string) (IfaceBytes, bool) {
	for _, i := range l {
		if i.Name == name {
			return i, true
		}
	}
	return IfaceBytes{}, false
}

func findPID(comm string) int {
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err == nil && strings.TrimSpace(string(b)) == comm {
			return pid
		}
	}
	return 0
}

// readTemp — температура процессора (k10temp у AMD, coretemp у Intel), °C.
func readTemp() float64 {
	dirs, _ := filepath.Glob("/sys/class/hwmon/hwmon*")
	for _, d := range dirs {
		name, err := os.ReadFile(filepath.Join(d, "name"))
		if err != nil {
			continue
		}
		switch strings.TrimSpace(string(name)) {
		case "k10temp", "coretemp":
			b, err := os.ReadFile(filepath.Join(d, "temp1_input"))
			if err != nil {
				continue
			}
			if v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64); err == nil {
				return v / 1000
			}
		}
	}
	return -1
}

var SystemHeader = []string{
	"time", "cpu_user", "cpu_sys", "cpu_irq", "cpu_softirq", "cpu_iowait", "cpu_idle",
	"mem_used_mb", "mem_avail_mb", "swap_used_mb", "disk_write_kbps", "disk_written_mb",
	"temp_c", "proc_pid", "proc_rss_mb", "proc_cpu_pct",
}

func (r Row) Record() []string {
	f := func(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }
	return []string{
		r.At.Format(time.RFC3339), f(r.CPU.User), f(r.CPU.System), f(r.CPU.IRQ), f(r.CPU.SoftIRQ),
		f(r.CPU.IOWait), f(r.CPU.Idle), f(r.MemUsedMB), f(r.MemAvailMB), f(r.SwapUsedMB),
		f(r.DiskWriteKBps), f(r.DiskWrittenMB), f(r.TempC), strconv.Itoa(r.ProcPID),
		f(r.ProcRSSMB), f(r.ProcCPUPct),
	}
}

var NetHeader = []string{"time", "netns", "iface", "rx_mbps", "tx_mbps", "rx_total_mb", "tx_total_mb"}

func (n NetRow) Record() []string {
	f := func(v float64) string { return strconv.FormatFloat(v, 'f', 3, 64) }
	return []string{n.At.Format(time.RFC3339), n.Netns, n.Iface, f(n.RxMbps), f(n.TxMbps), f(n.RxTotalMB), f(n.TxTotalMB)}
}
