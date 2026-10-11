// Package config — YAML-конфигурация демона: загрузка, значения по
// умолчанию, проверка. Описание полей — в configs/example.yaml.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"go.yaml.in/yaml/v3"

	"tross/core/lists"
	"tross/core/model"
)

type Config struct {
	Daemon  Daemon  `yaml:"daemon"`
	Log     Log     `yaml:"log"`
	API     API     `yaml:"api"`
	LAN     LAN     `yaml:"lan"`
	Links   []Link  `yaml:"links"`
	Monitor Monitor `yaml:"monitor"`
	Classes []Class `yaml:"classes"`
	DNS     DNS     `yaml:"dns"`
	Lists   Lists   `yaml:"lists"`
	DPI     DPI     `yaml:"dpi"`
	Proxy   Proxy   `yaml:"proxy"`
	Devices Devices `yaml:"devices"`
}

type Daemon struct {
	// DryRun — ничего не менять в системе: фейковые dataplane и монитор.
	DryRun  bool   `yaml:"dry_run"`
	DataDir string `yaml:"data_dir"`
}

type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	// RingSize — сколько свежих записей держать в памяти для интерфейса.
	RingSize int `yaml:"ring_size"`
}

type API struct {
	Listen string `yaml:"listen"`
	// AllowedNetworks — откуда разрешён доступ; по умолчанию сети LAN и loopback.
	AllowedNetworks []netip.Prefix `yaml:"allowed_networks"`
}

type LAN struct {
	Interface string         `yaml:"interface"`
	Networks  []netip.Prefix `yaml:"networks"`
}

type Link struct {
	ID        model.LinkID   `yaml:"id"`
	Name      string         `yaml:"name"`
	Kind      model.LinkKind `yaml:"kind"`
	Interface string         `yaml:"interface"`
	// Gateway — "auto" (из DHCP) или IP-адрес шлюза.
	Gateway string `yaml:"gateway"`
	// Metered по умолчанию true для LTE.
	Metered  *bool `yaml:"metered"`
	Priority int   `yaml:"priority"`
	// Table и FwMark по умолчанию выводятся из порядкового номера канала.
	Table  int    `yaml:"table"`
	FwMark uint32 `yaml:"fwmark"`
	// ProbeTargets — свои цели проверок; пусто — общие из monitor.targets.
	ProbeTargets       []netip.Addr `yaml:"probe_targets"`
	SQM                SQM          `yaml:"sqm"`
	Quota              *Quota       `yaml:"quota"`
	WhitelistDetection bool         `yaml:"whitelist_detection"`
}

// SQM — CAKE на канале; нулевая скорость — брать из измерений монитора.
type SQM struct {
	Enabled  bool `yaml:"enabled"`
	DownMbit int  `yaml:"down_mbit"`
	UpMbit   int  `yaml:"up_mbit"`
}

type Quota struct {
	MonthlyGB int `yaml:"monthly_gb"`
	ResetDay  int `yaml:"reset_day"`
}

type Monitor struct {
	Targets  []netip.Addr  `yaml:"targets"`
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	// Window — сколько последних проб учитывать в задержке, джиттере и потерях.
	Window int `yaml:"window"`
	// FailAfter / RecoverAfter — гистерезис: подряд неудачных раундов до «down»
	// и подряд удачных до возврата в «up».
	FailAfter    int `yaml:"fail_after"`
	RecoverAfter int `yaml:"recover_after"`
	// WhitelistTargets — цели, доступные и в режиме «белых списков» оператора;
	// у каналов с whitelist_detection исключаются из общих целей.
	WhitelistTargets []netip.Addr `yaml:"whitelist_targets"`
	// TCPFallbackPort — запасная проба, если ICMP режется по пути.
	TCPFallbackPort uint16    `yaml:"tcp_fallback_port"`
	HTTPCheck       HTTPCheck `yaml:"http_check"`
	SpeedTest       SpeedTest `yaml:"speedtest"`
}

// HTTPCheck — проверка «настоящего» интернета через канал: ping может
// проходить, а HTTP — резаться или подменяться (captive portal, «белые
// списки»). Неудача FailAfter раз подряд → канал restricted.
type HTTPCheck struct {
	Enabled   *bool          `yaml:"enabled"`
	Interval  time.Duration  `yaml:"interval"`
	Timeout   time.Duration  `yaml:"timeout"`
	FailAfter int            `yaml:"fail_after"`
	DNS       []netip.Addr   `yaml:"dns"` // резолверы, к которым идут запросы через канал
	URLs      []HTTPCheckURL `yaml:"urls"`
}

// HTTPCheckURL — адрес и ожидаемый ответ; Body — подстрока тела (пусто — не проверять).
type HTTPCheckURL struct {
	URL    string `yaml:"url"`
	Status int    `yaml:"status"`
	Body   string `yaml:"body"`
}

// SpeedTest — активный замер скорости: на проводных каналах раз в сутки в At,
// на лимитированных (LTE) — никогда автоматически, только по команде.
type SpeedTest struct {
	// URLs пробуются по порядку: следующий — если предыдущий не отдал данных.
	URLs     []string      `yaml:"urls"`
	At       string        `yaml:"at"` // "ЧЧ:ММ" местного времени
	Duration time.Duration `yaml:"duration"`
	MaxBytes int64         `yaml:"max_bytes"`
}

// AtClock разбирает At; ok=false при ошибке формата.
func (s SpeedTest) AtClock() (hour, minute int, ok bool) {
	t, err := time.Parse("15:04", s.At)
	if err != nil {
		return 0, 0, false
	}
	return t.Hour(), t.Minute(), true
}

// ProbeTargets — общие цели и цели белого списка для канала.
func (c *Config) ProbeTargets(l Link) (general, whitelist []netip.Addr) {
	targets := l.ProbeTargets
	if len(targets) == 0 {
		targets = c.Monitor.Targets
	}
	if !l.WhitelistDetection {
		return targets, nil
	}
	wl := make(map[netip.Addr]bool, len(c.Monitor.WhitelistTargets))
	for _, a := range c.Monitor.WhitelistTargets {
		wl[a] = true
	}
	for _, a := range targets {
		if !wl[a] {
			general = append(general, a)
		}
	}
	return general, c.Monitor.WhitelistTargets
}

type Class struct {
	ID           model.TrafficClass `yaml:"id"`
	Name         string             `yaml:"name"`
	model.Policy `yaml:",inline"`
}

type DNS struct {
	Listen    []string     `yaml:"listen"`
	Upstreams []Upstream   `yaml:"upstreams"`
	Bootstrap []netip.Addr `yaml:"bootstrap"`
	CacheSize int          `yaml:"cache_size"`
	// SetTTL — пределы таймаута записи в множествах nftables (TTL ответа обрезается).
	SetTTL                TTLRange `yaml:"set_ttl"`
	FirefoxCanaryNXDomain *bool    `yaml:"firefox_canary_nxdomain"`
	Watchdog              Watchdog `yaml:"watchdog"`
}

// Upstream — https://… (DoH) или tls://хост[:порт] (DoT).
type Upstream struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

type TTLRange struct {
	Min time.Duration `yaml:"min"`
	Max time.Duration `yaml:"max"`
}

type Watchdog struct {
	Interval time.Duration `yaml:"interval"`
	Failures int           `yaml:"failures"`
}

type Lists struct {
	UpdateInterval time.Duration  `yaml:"update_interval"`
	Sources        []lists.Source `yaml:"sources"`
}

type DPI struct {
	Enabled bool   `yaml:"enabled"`
	NFQWS   string `yaml:"nfqws"`
	// QueueBase — номер NFQUEUE первого канала; остальные идут подряд.
	QueueBase       uint16        `yaml:"queue_base"`
	RecheckInterval time.Duration `yaml:"recheck_interval"`
	ProbeDomains    []string      `yaml:"probe_domains"`
}

type Proxy struct {
	Enabled bool   `yaml:"enabled"`
	Engine  string `yaml:"engine"`
	Binary  string `yaml:"binary"`
	// Version — ожидаемая версия бинарника; при несовпадении ядро не запускается.
	Version         string `yaml:"version"`
	WorkDir         string `yaml:"work_dir"`
	Controller      string `yaml:"controller"`
	TProxyPortBase  uint16 `yaml:"tproxy_port_base"`
	RoutingMarkBase uint32 `yaml:"routing_mark_base"`
}

type Devices struct {
	NotifyNew      *bool         `yaml:"notify_new"`
	DefaultDNSMode model.DNSMode `yaml:"default_dns_mode"`
}

// Load читает, дополняет значениями по умолчанию и проверяет конфигурацию.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func Parse(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// Опечатка в имени поля должна быть ошибкой, а не тихим значением по умолчанию.
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ModelLinks — каналы в виде моделей core.
func (c *Config) ModelLinks() []model.Link {
	out := make([]model.Link, 0, len(c.Links))
	for _, l := range c.Links {
		out = append(out, l.Model())
	}
	return out
}

func (l Link) Model() model.Link {
	return model.Link{
		ID:        l.ID,
		Name:      l.Name,
		Kind:      l.Kind,
		Interface: l.Interface,
		Metered:   l.Metered != nil && *l.Metered,
		Priority:  l.Priority,
	}
}

// GatewayAddr — адрес шлюза; невалидный при "auto".
func (l Link) GatewayAddr() netip.Addr {
	a, err := netip.ParseAddr(l.Gateway)
	if err != nil {
		return netip.Addr{}
	}
	return a
}

// Policies — политики классов по идентификатору.
func (c *Config) Policies() map[model.TrafficClass]model.Policy {
	out := make(map[model.TrafficClass]model.Policy, len(c.Classes))
	for _, cl := range c.Classes {
		out[cl.ID] = cl.Policy
	}
	return out
}

var errNoLinks = errors.New("links: at least one link is required")
