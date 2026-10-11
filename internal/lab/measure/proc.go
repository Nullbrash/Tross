// Package measure — замеры ресурсов на стенде: разбор /proc и /sys, расчёт
// приращений между выборками. Используется утилитой cmd/labmeasure.
package measure

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// CPUTimes — счётчики строки "cpu" из /proc/stat (в тиках).
type CPUTimes struct {
	User, Nice, System, Idle, IOWait, IRQ, SoftIRQ, Steal uint64
}

func (c CPUTimes) Total() uint64 {
	return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
}

// ParseCPU разбирает суммарную строку "cpu" из /proc/stat.
func ParseCPU(stat string) (CPUTimes, error) {
	for line := range strings.Lines(stat) {
		f := strings.Fields(line)
		if len(f) < 9 || f[0] != "cpu" {
			continue
		}
		v := make([]uint64, 8)
		for i := range v {
			n, err := strconv.ParseUint(f[i+1], 10, 64)
			if err != nil {
				return CPUTimes{}, fmt.Errorf("cpu field %d: %w", i+1, err)
			}
			v[i] = n
		}
		return CPUTimes{v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]}, nil
	}
	return CPUTimes{}, fmt.Errorf("no cpu line in /proc/stat")
}

// CPUShare — доли времени процессора между двумя выборками, в процентах.
type CPUShare struct {
	User, System, IRQ, SoftIRQ, IOWait, Idle float64
}

func CPUDelta(a, b CPUTimes) CPUShare {
	total := float64(b.Total() - a.Total())
	if total <= 0 {
		return CPUShare{Idle: 100}
	}
	pct := func(x, y uint64) float64 { return float64(y-x) * 100 / total }
	return CPUShare{
		User:    pct(a.User+a.Nice, b.User+b.Nice),
		System:  pct(a.System, b.System),
		IRQ:     pct(a.IRQ, b.IRQ),
		SoftIRQ: pct(a.SoftIRQ, b.SoftIRQ),
		IOWait:  pct(a.IOWait, b.IOWait),
		Idle:    pct(a.Idle, b.Idle),
	}
}

// Mem — память системы в КиБ.
type Mem struct {
	TotalKB, AvailableKB, SwapUsedKB uint64
}

func ParseMeminfo(s string) (Mem, error) {
	vals := map[string]uint64{}
	for line := range strings.Lines(s) {
		k, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		if n, err := strconv.ParseUint(f[0], 10, 64); err == nil {
			vals[k] = n
		}
	}
	total, ok1 := vals["MemTotal"]
	avail, ok2 := vals["MemAvailable"]
	if !ok1 || !ok2 {
		return Mem{}, fmt.Errorf("meminfo: MemTotal/MemAvailable missing")
	}
	return Mem{TotalKB: total, AvailableKB: avail, SwapUsedKB: vals["SwapTotal"] - vals["SwapFree"]}, nil
}

// ParseDiskSectorsWritten возвращает счётчик записанных секторов (по 512 байт)
// устройства из /proc/diskstats.
func ParseDiskSectorsWritten(diskstats, dev string) (uint64, error) {
	for line := range strings.Lines(diskstats) {
		f := strings.Fields(line)
		if len(f) >= 10 && f[2] == dev {
			return strconv.ParseUint(f[9], 10, 64)
		}
	}
	return 0, fmt.Errorf("device %q not found in diskstats", dev)
}

// ProcStat — счётчики процесса из /proc/<pid>/stat и status.
type ProcStat struct {
	UTime, STime uint64 // тики
	RSSKB        uint64
}

// ParseProcStat разбирает /proc/<pid>/stat. Имя процесса в скобках может
// содержать пробелы и ')' — поэтому поля считаются от последней ')'.
func ParseProcStat(stat string) (utime, stime uint64, err error) {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, 0, fmt.Errorf("bad stat")
	}
	f := strings.Fields(stat[i+1:])
	// После ')' поле 0 — state (3-е в man proc), utime — 14-е, stime — 15-е.
	if len(f) < 13 {
		return 0, 0, fmt.Errorf("short stat")
	}
	if utime, err = strconv.ParseUint(f[11], 10, 64); err != nil {
		return 0, 0, err
	}
	stime, err = strconv.ParseUint(f[12], 10, 64)
	return utime, stime, err
}

// ParseVmRSS достаёт VmRSS (КиБ) из /proc/<pid>/status.
func ParseVmRSS(status string) (uint64, error) {
	sc := bufio.NewScanner(strings.NewReader(status))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "VmRSS:"); ok {
			f := strings.Fields(v)
			if len(f) > 0 {
				return strconv.ParseUint(f[0], 10, 64)
			}
		}
	}
	return 0, fmt.Errorf("VmRSS not found")
}

// IfaceBytes — счётчики байт интерфейса.
type IfaceBytes struct {
	Name    string
	RxBytes uint64
	TxBytes uint64
}

// ParseIPLinkJSON разбирает вывод `ip -s -j link show`.
func ParseIPLinkJSON(b []byte) ([]IfaceBytes, error) {
	var links []struct {
		Ifname string `json:"ifname"`
		Stats  struct {
			Rx struct {
				Bytes uint64 `json:"bytes"`
			} `json:"rx"`
			Tx struct {
				Bytes uint64 `json:"bytes"`
			} `json:"tx"`
		} `json:"stats64"`
	}
	if err := json.Unmarshal(b, &links); err != nil {
		return nil, err
	}
	out := make([]IfaceBytes, 0, len(links))
	for _, l := range links {
		if l.Ifname == "lo" {
			continue
		}
		out = append(out, IfaceBytes{Name: l.Ifname, RxBytes: l.Stats.Rx.Bytes, TxBytes: l.Stats.Tx.Bytes})
	}
	return out, nil
}
