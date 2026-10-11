package measure

import (
	"fmt"
	"io"
	"sort"
)

// Summary накапливает итоги прогона для summary.txt.
type Summary struct {
	n                                 int
	busy, softirq, mem, proc, procRSS stat
	diskKBps, temp                    stat
	lastDiskMB                        float64
	net                               map[string]*netStat
}

type stat struct{ sum, max float64 }

func (s *stat) add(v float64) {
	s.sum += v
	if v > s.max {
		s.max = v
	}
}

type netStat struct {
	rx, tx     stat
	rxMB, txMB float64
}

func (s *Summary) Add(r Row, nets []NetRow) {
	s.n++
	s.busy.add(100 - r.CPU.Idle)
	s.softirq.add(r.CPU.SoftIRQ)
	s.mem.add(r.MemUsedMB)
	s.proc.add(r.ProcCPUPct)
	s.procRSS.add(r.ProcRSSMB)
	s.diskKBps.add(r.DiskWriteKBps)
	s.temp.add(r.TempC)
	s.lastDiskMB = r.DiskWrittenMB
	if s.net == nil {
		s.net = map[string]*netStat{}
	}
	for _, n := range nets {
		k := n.Netns + "/" + n.Iface
		ns := s.net[k]
		if ns == nil {
			ns = &netStat{}
			s.net[k] = ns
		}
		ns.rx.add(n.RxMbps)
		ns.tx.add(n.TxMbps)
		ns.rxMB, ns.txMB = n.RxTotalMB, n.TxTotalMB
	}
}

func (s *Summary) Write(w io.Writer, durationSec float64) {
	if s.n == 0 {
		fmt.Fprintln(w, "no samples")
		return
	}
	avg := func(x stat) float64 { return x.sum / float64(s.n) }
	fmt.Fprintf(w, "samples: %d, duration: %.0f s\n", s.n, durationSec)
	fmt.Fprintf(w, "cpu busy %%:        avg %6.2f  max %6.2f\n", avg(s.busy), s.busy.max)
	fmt.Fprintf(w, "cpu softirq %%:     avg %6.2f  max %6.2f   (обработка пакетов ядром)\n", avg(s.softirq), s.softirq.max)
	fmt.Fprintf(w, "mem used MB:       avg %6.1f  max %6.1f\n", avg(s.mem), s.mem.max)
	fmt.Fprintf(w, "proc cpu %% (1 ядро): avg %6.2f  max %6.2f\n", avg(s.proc), s.proc.max)
	fmt.Fprintf(w, "proc rss MB:       avg %6.1f  max %6.1f\n", avg(s.procRSS), s.procRSS.max)
	fmt.Fprintf(w, "disk write KB/s:   avg %6.1f  max %6.1f   total %.2f MB\n", avg(s.diskKBps), s.diskKBps.max, s.lastDiskMB)
	if durationSec > 0 {
		fmt.Fprintf(w, "disk write MB/day (экстраполяция): %.1f\n", s.lastDiskMB/durationSec*86400)
	}
	fmt.Fprintf(w, "temp C:            avg %6.1f  max %6.1f\n", avg(s.temp), s.temp.max)
	keys := make([]string, 0, len(s.net))
	for k := range s.net {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		n := s.net[k]
		fmt.Fprintf(w, "net %-22s rx avg %7.2f max %7.2f Mbit/s, tx avg %7.2f max %7.2f Mbit/s, total rx %.1f MB tx %.1f MB\n",
			k, avg(n.rx), n.rx.max, avg(n.tx), n.tx.max, n.rxMB, n.txMB)
	}
}
