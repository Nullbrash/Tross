package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"tross/core/event"
	"tross/core/model"
)

// SQLite — хранилище на одном файле базы (или в памяти — для тестов и
// сухого режима без каталога данных).
type SQLite struct {
	db     *sql.DB
	path   string
	ret    Retention
	closed atomic.Bool
}

var _ Store = (*SQLite)(nil)

// Open открывает (создаёт) базу по пути; пустой путь — база в памяти.
func Open(path string, ret Retention) (*SQLite, error) {
	dsn := "file::memory:"
	if path != "" {
		// WAL + synchronous=NORMAL: запись без fsync на каждую транзакцию —
		// меньше износ SSD; при сбое питания теряется только последняя пачка.
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	}
	db, err := sql.Open("sqlite", dsn+sep(dsn)+"_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	// Одно соединение: база в памяти живёт в соединении, а писатель у нас один.
	db.SetMaxOpenConns(1)
	s := &SQLite{db: db, path: path, ret: ret}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return s, nil
}

func sep(dsn string) string {
	if slices.Contains([]byte(dsn), '?') {
		return "&"
	}
	return "?"
}

// migrations — только добавлять в конец: номер версии = индекс + 1.
var migrations = []string{
	`CREATE TABLE devices (id TEXT PRIMARY KEY, data TEXT NOT NULL);
	 CREATE TABLE rules (layer TEXT, match TEXT, pattern TEXT, data TEXT NOT NULL, PRIMARY KEY (layer, match, pattern)) WITHOUT ROWID;
	 CREATE TABLE events (id INTEGER PRIMARY KEY, at INTEGER NOT NULL, topic TEXT NOT NULL, data TEXT);
	 CREATE INDEX events_at ON events (at);
	 CREATE TABLE link_minute (link TEXT, at INTEGER, state TEXT, rtt REAL, jitter REAL, loss REAL, rx INTEGER, tx INTEGER, PRIMARY KEY (link, at)) WITHOUT ROWID;
	 CREATE TABLE sys_minute (at INTEGER PRIMARY KEY, cpu REAL, softirq REAL, mem REAL, proc_cpu REAL, rss REAL, disk_kb REAL);
	 CREATE TABLE link_agg (res TEXT, link TEXT, at INTEGER, samples INTEGER, usable INTEGER,
	   rtt_min REAL, rtt_avg REAL, rtt_max REAL, rtt_p95 REAL, jitter_avg REAL, jitter_p95 REAL,
	   loss_avg REAL, loss_max REAL, rx INTEGER, tx INTEGER, PRIMARY KEY (res, link, at)) WITHOUT ROWID;
	 CREATE TABLE sys_agg (res TEXT, at INTEGER, samples INTEGER, cpu_avg REAL, cpu_max REAL, cpu_p95 REAL,
	   softirq_avg REAL, softirq_max REAL, mem_avg REAL, mem_max REAL, proc_cpu_avg REAL, proc_cpu_max REAL,
	   proc_cpu_p95 REAL, rss_avg REAL, rss_max REAL, disk_kb REAL, PRIMARY KEY (res, at)) WITHOUT ROWID;
	 CREATE TABLE rollup_state (res TEXT PRIMARY KEY, done_until INTEGER NOT NULL);`,
}

func (s *SQLite) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (v INTEGER NOT NULL)`); err != nil {
		return err
	}
	var v int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(v), 0) FROM schema_version`).Scan(&v); err != nil {
		return err
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(`DELETE FROM schema_version; INSERT INTO schema_version VALUES (?)`, i+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLite) check() error {
	if s.closed.Load() {
		return ErrClosed
	}
	return nil
}

func (s *SQLite) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	return s.db.Close()
}

func (s *SQLite) SizeBytes() int64 {
	if s.path == "" {
		return 0
	}
	var n int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if fi, err := os.Stat(s.path + suffix); err == nil {
			n += fi.Size()
		}
	}
	return n
}

// --- устройства и правила ------------------------------------------------

func (s *SQLite) SaveDevice(ctx context.Context, d model.Device) error {
	if err := s.check(); err != nil {
		return err
	}
	if d.ID == "" {
		return errors.New("store: device id is empty")
	}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO devices (id, data) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET data = excluded.data`, d.ID, b)
	return err
}

func (s *SQLite) DeleteDevice(ctx context.Context, id string) error {
	if err := s.check(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id)
	return err
}

func (s *SQLite) Devices(ctx context.Context) ([]model.Device, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM devices ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Device
	for rows.Next() {
		var b []byte
		var d model.Device
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *SQLite) SaveRule(ctx context.Context, r model.DomainRule) error {
	if err := s.check(); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO rules (layer, match, pattern, data) VALUES (?, ?, ?, ?)
		ON CONFLICT (layer, match, pattern) DO UPDATE SET data = excluded.data`, r.Layer, r.Match, r.Pattern, b)
	return err
}

func (s *SQLite) DeleteRule(ctx context.Context, k RuleKey) error {
	if err := s.check(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM rules WHERE layer = ? AND match = ? AND pattern = ?`, k.Layer, k.Match, k.Pattern)
	return err
}

func (s *SQLite) Rules(ctx context.Context, layer model.RuleLayer) ([]model.DomainRule, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM rules WHERE layer = ? ORDER BY pattern, match`, layer)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.DomainRule
	for rows.Next() {
		var b []byte
		var r model.DomainRule
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- события -------------------------------------------------------------

func (s *SQLite) AppendEvent(ctx context.Context, e event.Event) error {
	if err := s.check(); err != nil {
		return err
	}
	b, err := json.Marshal(e.Data)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO events (at, topic, data) VALUES (?, ?, ?)`, e.Time.UnixMilli(), e.Topic, string(b))
	return err
}

func (s *SQLite) Events(ctx context.Context, since time.Time, limit int) ([]event.Event, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = math.MaxInt32
	}
	rows, err := s.db.QueryContext(ctx, `SELECT at, topic, data FROM (
		SELECT id, at, topic, data FROM events WHERE at >= ? ORDER BY at DESC, id DESC LIMIT ?) ORDER BY at, id`,
		since.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []event.Event
	for rows.Next() {
		var at int64
		var topic, data string
		if err := rows.Scan(&at, &topic, &data); err != nil {
			return nil, err
		}
		out = append(out, event.Event{Topic: event.Topic(topic), Time: time.UnixMilli(at), Data: json.RawMessage(data)})
	}
	return out, rows.Err()
}

// --- статистика ----------------------------------------------------------

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func (s *SQLite) AppendSamples(ctx context.Context, links []LinkSample, sys *SystemSample) error {
	if err := s.check(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, l := range links {
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO link_minute (link, at, state, rtt, jitter, loss, rx, tx) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			l.Link, l.At.Unix(), l.State, ms(l.RTT), ms(l.Jitter), l.Loss, int64(l.RxBytes), int64(l.TxBytes)); err != nil {
			return err
		}
	}
	if sys != nil {
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO sys_minute (at, cpu, softirq, mem, proc_cpu, rss, disk_kb) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			sys.At.Unix(), sys.CPUBusy, sys.CPUSoftIRQ, sys.MemUsedMB, sys.ProcCPU, sys.ProcRSSMB, sys.DiskWriteKB); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Rollup досчитывает сводки за закрытые часы и дни (UTC) из поминутных строк
// и только потом удаляет устаревшее. Состояние — в rollup_state, поэтому после
// простоя демона пропущенные интервалы досчитываются из оставшихся минут.
func (s *SQLite) Rollup(ctx context.Context, now time.Time) error {
	if err := s.check(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, res := range []Resolution{ResHour, ResDay} {
		if err := rollupRes(ctx, tx, res, now); err != nil {
			return fmt.Errorf("rollup %s: %w", res, err)
		}
	}
	prune := []struct {
		q   string
		age time.Duration
	}{
		{`DELETE FROM link_minute WHERE at < ?`, s.ret.Minute},
		{`DELETE FROM sys_minute WHERE at < ?`, s.ret.Minute},
		{`DELETE FROM link_agg WHERE res = 'hour' AND at < ?`, s.ret.Hour},
		{`DELETE FROM sys_agg WHERE res = 'hour' AND at < ?`, s.ret.Hour},
		{`DELETE FROM link_agg WHERE res = 'day' AND at < ?`, s.ret.Day},
		{`DELETE FROM sys_agg WHERE res = 'day' AND at < ?`, s.ret.Day},
	}
	for _, p := range prune {
		if _, err := tx.ExecContext(ctx, p.q, now.Add(-p.age).Unix()); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE at < ?`, now.Add(-s.ret.Events).UnixMilli()); err != nil {
		return err
	}
	return tx.Commit()
}

func rollupRes(ctx context.Context, tx *sql.Tx, res Resolution, now time.Time) error {
	step := int64(res.Step() / time.Second)
	// Эпоха Unix выровнена по UTC-суткам, поэтому at - at%step — начало часа/дня.
	end := now.Unix() - now.Unix()%step // закрытые интервалы — строго до текущего
	var done int64
	if err := tx.QueryRowContext(ctx, `SELECT done_until FROM rollup_state WHERE res = ?`, res).Scan(&done); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if end <= done {
		return nil
	}
	// Только интервалы, где есть данные: после долгого простоя не перебираем пустые.
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT at - at % ?1 FROM (SELECT at FROM link_minute UNION ALL SELECT at FROM sys_minute)
		WHERE at >= ?2 AND at < ?3 ORDER BY 1`, step, done, end)
	if err != nil {
		return err
	}
	var buckets []int64
	for rows.Next() {
		var b int64
		if err := rows.Scan(&b); err != nil {
			rows.Close()
			return err
		}
		buckets = append(buckets, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, b := range buckets {
		if err := aggregateBucket(ctx, tx, res, time.Unix(b, 0), time.Unix(b+step, 0)); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO rollup_state (res, done_until) VALUES (?, ?) ON CONFLICT (res) DO UPDATE SET done_until = excluded.done_until`, res, end)
	return err
}

func aggregateBucket(ctx context.Context, tx *sql.Tx, res Resolution, from, to time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT link, state, rtt, jitter, loss, rx, tx FROM link_minute WHERE at >= ? AND at < ? ORDER BY link`, from.Unix(), to.Unix())
	if err != nil {
		return err
	}
	type acc struct {
		usable            int
		rtt, jitter, loss []float64
		rx, tx            uint64
	}
	byLink := map[string]*acc{}
	for rows.Next() {
		var link, state string
		var rtt, jitter, loss float64
		var rx, txb int64
		if err := rows.Scan(&link, &state, &rtt, &jitter, &loss, &rx, &txb); err != nil {
			rows.Close()
			return err
		}
		a := byLink[link]
		if a == nil {
			a = &acc{}
			byLink[link] = a
		}
		if model.LinkState(state).Usable() {
			a.usable++
		}
		// Задержка непригодного канала (0 или мусор) искажала бы сводку.
		if rtt > 0 {
			a.rtt = append(a.rtt, rtt)
			a.jitter = append(a.jitter, jitter)
		}
		a.loss = append(a.loss, loss)
		a.rx += uint64(rx)
		a.tx += uint64(txb)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for link, a := range byLink {
		r, j, l := summarize(a.rtt), summarize(a.jitter), summarize(a.loss)
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO link_agg (res, link, at, samples, usable, rtt_min, rtt_avg, rtt_max, rtt_p95, jitter_avg, jitter_p95, loss_avg, loss_max, rx, tx)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			res, link, from.Unix(), len(a.loss), a.usable, r.min, r.avg, r.max, r.p95, j.avg, j.p95, l.avg, l.max, int64(a.rx), int64(a.tx)); err != nil {
			return err
		}
	}

	var cpu, soft, mem, pcpu, rss []float64
	var disk float64
	srows, err := tx.QueryContext(ctx, `SELECT cpu, softirq, mem, proc_cpu, rss, disk_kb FROM sys_minute WHERE at >= ? AND at < ?`, from.Unix(), to.Unix())
	if err != nil {
		return err
	}
	for srows.Next() {
		var c, so, m, pc, r, d float64
		if err := srows.Scan(&c, &so, &m, &pc, &r, &d); err != nil {
			srows.Close()
			return err
		}
		cpu, soft, mem, pcpu, rss = append(cpu, c), append(soft, so), append(mem, m), append(pcpu, pc), append(rss, r)
		disk += d
	}
	srows.Close()
	if err := srows.Err(); err != nil {
		return err
	}
	if len(cpu) == 0 {
		return nil
	}
	c, so, m, pc, r := summarize(cpu), summarize(soft), summarize(mem), summarize(pcpu), summarize(rss)
	_, err = tx.ExecContext(ctx, `INSERT OR REPLACE INTO sys_agg (res, at, samples, cpu_avg, cpu_max, cpu_p95, softirq_avg, softirq_max, mem_avg, mem_max, proc_cpu_avg, proc_cpu_max, proc_cpu_p95, rss_avg, rss_max, disk_kb)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		res, from.Unix(), len(cpu), c.avg, c.max, c.p95, so.avg, so.max, m.avg, m.max, pc.avg, pc.max, pc.p95, r.avg, r.max, disk)
	return err
}

type stats struct{ min, avg, max, p95 float64 }

// summarize — min/avg/max и p95 по ближайшему рангу.
func summarize(v []float64) stats {
	if len(v) == 0 {
		return stats{}
	}
	s := slices.Clone(v)
	slices.Sort(s)
	var sum float64
	for _, x := range s {
		sum += x
	}
	rank := int(math.Ceil(0.95*float64(len(s)))) - 1
	return stats{min: s[0], avg: sum / float64(len(s)), max: s[len(s)-1], p95: s[max(rank, 0)]}
}

func (s *SQLite) LinkStats(ctx context.Context, link model.LinkID, res Resolution, from, to time.Time) ([]LinkStat, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	var rows *sql.Rows
	var err error
	if res == ResMinute {
		rows, err = s.db.QueryContext(ctx, `SELECT at, 1, CASE WHEN state IN ('up', 'degraded') THEN 1 ELSE 0 END, rtt, rtt, rtt, rtt, jitter, jitter, loss, loss, rx, tx
			FROM link_minute WHERE link = ? AND at >= ? AND at < ? ORDER BY at`, link, from.Unix(), to.Unix())
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT at, samples, usable, rtt_min, rtt_avg, rtt_max, rtt_p95, jitter_avg, jitter_p95, loss_avg, loss_max, rx, tx
			FROM link_agg WHERE res = ? AND link = ? AND at >= ? AND at < ? ORDER BY at`, res, link, from.Unix(), to.Unix())
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LinkStat
	for rows.Next() {
		var at, rx, tx int64
		st := LinkStat{Link: link}
		if err := rows.Scan(&at, &st.Samples, &st.UsableMinutes, &st.RTTMin, &st.RTTAvg, &st.RTTMax, &st.RTTP95,
			&st.JitterAvg, &st.JitterP95, &st.LossAvg, &st.LossMax, &rx, &tx); err != nil {
			return nil, err
		}
		st.At, st.RxBytes, st.TxBytes = time.Unix(at, 0).UTC(), uint64(rx), uint64(tx)
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *SQLite) SystemStats(ctx context.Context, res Resolution, from, to time.Time) ([]SystemStat, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	var rows *sql.Rows
	var err error
	if res == ResMinute {
		rows, err = s.db.QueryContext(ctx, `SELECT at, 1, cpu, cpu, cpu, softirq, softirq, mem, mem, proc_cpu, proc_cpu, proc_cpu, rss, rss, disk_kb
			FROM sys_minute WHERE at >= ? AND at < ? ORDER BY at`, from.Unix(), to.Unix())
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT at, samples, cpu_avg, cpu_max, cpu_p95, softirq_avg, softirq_max, mem_avg, mem_max, proc_cpu_avg, proc_cpu_max, proc_cpu_p95, rss_avg, rss_max, disk_kb
			FROM sys_agg WHERE res = ? AND at >= ? AND at < ? ORDER BY at`, res, from.Unix(), to.Unix())
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SystemStat
	for rows.Next() {
		var at int64
		var st SystemStat
		if err := rows.Scan(&at, &st.Samples, &st.CPUAvg, &st.CPUMax, &st.CPUP95, &st.SoftIRQAvg, &st.SoftIRQMax,
			&st.MemAvgMB, &st.MemMaxMB, &st.ProcCPUAvg, &st.ProcCPUMax, &st.ProcCPUP95, &st.RSSAvgMB, &st.RSSMaxMB, &st.DiskWriteKB); err != nil {
			return nil, err
		}
		st.At = time.Unix(at, 0).UTC()
		out = append(out, st)
	}
	return out, rows.Err()
}
