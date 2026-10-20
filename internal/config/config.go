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

	coredns "tross/core/dns"
	coredpi "tross/core/dpi"
	"tross/core/lists"
	"tross/core/model"
	"tross/core/profile"
	"tross/core/sqm"
)

type Config struct {
	Daemon   Daemon   `yaml:"daemon"`
	Log      Log      `yaml:"log"`
	API      API      `yaml:"api"`
	LAN      LAN      `yaml:"lan"`
	Links    []Link   `yaml:"links"`
	Monitor  Monitor  `yaml:"monitor"`
	Classes  []Class  `yaml:"classes"`
	Classify Classify `yaml:"classify"`
	Inbound  Inbound  `yaml:"inbound"`
	DNS      DNS      `yaml:"dns"`
	Lists    Lists    `yaml:"lists"`
	DPI      DPI      `yaml:"dpi"`
	Proxy    Proxy    `yaml:"proxy"`
	Devices  Devices  `yaml:"devices"`
}

type Daemon struct {
	// DryRun — ничего не менять в системе: фейковые dataplane и монитор.
	DryRun  bool   `yaml:"dry_run"`
	DataDir string `yaml:"data_dir"`
	// Control — сокет команд root (`trossd debug …`); в «сухом» режиме
	// не открывается.
	Control string `yaml:"control"`
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
	ProbeTargets []netip.Addr `yaml:"probe_targets"`
	SQM          SQM          `yaml:"sqm"`
	Quota        *Quota       `yaml:"quota"`
	// WhitelistDetection по умолчанию true: «белые списки» вводят и у проводных
	// провайдеров, а распознавание стоит только проб к российским целям.
	WhitelistDetection *bool `yaml:"whitelist_detection"`
}

// SQM — CAKE на канале. Скорость очереди = база × процент; база —
// down_mbit/up_mbit, а при нуле — из замеров (тест скорости, а у LTE —
// насыщение канала, увиденное по задержке).
type SQM struct {
	Enabled  bool `yaml:"enabled"`
	DownMbit int  `yaml:"down_mbit"`
	UpMbit   int  `yaml:"up_mbit"`
	// StartPct, MinPct, MaxPct — процент от базы: начальный и пределы
	// автоподстройки; по умолчанию 90 и 80–97 (LTE — 50–95).
	StartPct int `yaml:"start_pct"`
	MinPct   int `yaml:"min_pct"`
	MaxPct   int `yaml:"max_pct"`
	// Auto — подстраивать процент по задержке под нагрузкой; false —
	// всегда start_pct.
	Auto *bool `yaml:"auto"`
}

// Params — настройки очереди канала для core/sqm (после значений по умолчанию).
func (q SQM) Params(kind model.LinkKind) sqm.Params {
	p := sqm.ParamsFor(kind)
	p.Start, p.Min, p.Max = float64(q.StartPct)/100, float64(q.MinPct)/100, float64(q.MaxPct)/100
	p.Auto = q.Auto == nil || *q.Auto
	return p
}

type Quota struct {
	MonthlyGB int `yaml:"monthly_gb"`
	ResetDay  int `yaml:"reset_day"`
}

type Monitor struct {
	Targets  []netip.Addr  `yaml:"targets"`
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	// Window — сколько последних раундов проб учитывать в задержке, джиттере и
	// потерях (проб в окне больше: по пробе к каждой цели за раунд).
	Window int `yaml:"window"`
	// FailAfter / RecoverAfter — гистерезис: подряд неудачных раундов до «down»
	// и подряд удачных до возврата в «up».
	FailAfter    int `yaml:"fail_after"`
	RecoverAfter int `yaml:"recover_after"`
	// WhitelistTargets — российские цели в разных AS: доступны и в режиме
	// «белых списков»; у каналов с whitelist_detection исключаются из общих.
	WhitelistTargets []netip.Addr `yaml:"whitelist_targets"`
	// TCPTargets — TCP-пробы (по одной за раунд, по кругу): ICMP может
	// проходить, когда TCP режется, и наоборот.
	TCPTargets []netip.AddrPort `yaml:"tcp_targets"`
	HTTPCheck  HTTPCheck        `yaml:"http_check"`
	SpeedTest  SpeedTest        `yaml:"speedtest"`
}

// HTTPCheck — проверка «настоящего» интернета через канал: ping может
// проходить, а HTTP — резаться или подменяться (captive portal, «белые
// списки»). Неудача FailAfter раз подряд → канал restricted.
type HTTPCheck struct {
	Enabled   *bool          `yaml:"enabled"`
	Interval  time.Duration  `yaml:"interval"`
	Timeout   time.Duration  `yaml:"timeout"`
	FailAfter int            `yaml:"fail_after"`
	DNS       []DNSServer    `yaml:"dns"` // резолверы, к которым идут запросы через канал
	URLs      []HTTPCheckURL `yaml:"urls"`
}

// HTTPCheckURL — адрес и ожидаемый ответ; Body — подстрока тела (пусто — не
// проверять). Domestic — российский адрес: не засчитывается как «интернет
// есть», а различает «нет зарубежного» и «нет HTTP вовсе»; только https,
// Status 0 — любой ответ (страница авторизации не подделает сертификат).
type HTTPCheckURL struct {
	URL      string `yaml:"url"`
	Status   int    `yaml:"status"`
	Body     string `yaml:"body"`
	Domestic bool   `yaml:"domestic"`
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
	if l.WhitelistDetection == nil || !*l.WhitelistDetection {
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

// Classify — правила пользователя и свои профили сервисов поверх
// встроенного каталога (core/profile).
type Classify struct {
	Rules    []ClassifyRule    `yaml:"rules"`
	Services []profile.Service `yaml:"services"`
}

// ClassifyRule — правило пользователя: условие как в профилях и, по желанию,
// адреса устройств (до реестра устройств — по IPv4 из LAN).
type ClassifyRule struct {
	Name          string             `yaml:"name"`
	Class         model.TrafficClass `yaml:"class"`
	Devices       []netip.Addr       `yaml:"devices"`
	profile.Match `yaml:",inline"`
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
	// Race — сколько серверов быстрого набора спрашивать разом.
	Race      int       `yaml:"race"`
	Sensitive Sensitive `yaml:"sensitive"`
	// Fallback — запасной резолвер на мини-ПК (отдельная программа): ему
	// уходят DNS-запросы дома, пока демона нет.
	Fallback netip.AddrPort `yaml:"fallback"`
	// Devices — свой режим DNS устройства (остальным — devices.default_dns_mode).
	Devices []DNSDevice `yaml:"devices"`
	// CAFile — дополнительные корни для DoH/DoT (свой сервер, стенд).
	CAFile string `yaml:"ca_file"`
	// Hosts — свои имена: устройствам дома резолвер отвечает этим адресом,
	// наружу имя не спрашивает (сервер дома по тому же имени, что снаружи).
	Hosts map[string]netip.Addr `yaml:"hosts"`
}

type DNSDevice struct {
	Address netip.Addr    `yaml:"address"`
	Mode    model.DNSMode `yaml:"mode"`
}

// Upstream — https://… (DoH) или tls://хост[:порт] (DoT).
type Upstream struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	// Pools — в каких наборах сервер основной; пусто — только запасной.
	Pools []coredns.Pool `yaml:"pools"`
	// Backup — запасной для доли этого сервера в защищённом наборе.
	Backup string `yaml:"backup"`
	// TLSName — сертификат сервера, заданного по IP, выдан на имя (без IP):
	// проверять по этому имени; само имя наружу не уходит.
	TLSName string `yaml:"tls_name"`
}

// Sensitive — особо личное: DNS — только защищённым набором, домен
// закреплён за одним сервером.
type Sensitive struct {
	// Services — сервисы каталога профилей ("steam") или их части
	// ("steam/store").
	Services []string `yaml:"services"`
	Domains  []string `yaml:"domains"`
	// FallbackFast — защищённый набор недоступен целиком: временно спрашивать
	// быстрый. Выключено — особо личное не открывается, но имена не уходят.
	FallbackFast bool `yaml:"fallback_fast"`
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
	// Manual — свои правила: важнее выученных, встроенных и онлайн-списков.
	Manual []ListRule `yaml:"manual"`
}

// ListRule — своё правило для доменов (с поддоменами; Exact — только сам).
type ListRule struct {
	Domains []string           `yaml:"domains"`
	Exact   bool               `yaml:"exact"`
	Purpose lists.Purpose      `yaml:"purpose"`
	Class   model.TrafficClass `yaml:"class"`
}

// ManualRules — ручные правила для core/lists.
func (l Lists) ManualRules() []model.DomainRule {
	var out []model.DomainRule
	for _, r := range l.Manual {
		match := model.MatchSuffix
		if r.Exact {
			match = model.MatchExact
		}
		for _, d := range r.Domains {
			out = append(out, model.DomainRule{Pattern: d, Match: match, Purpose: r.Purpose, Class: r.Class, Source: "user"})
		}
	}
	return out
}

type DPI struct {
	Enabled bool `yaml:"enabled"`
	// NFQWS — движок nfqws2 (zapret2), LuaDir — его библиотеки; Version —
	// выпуск из файла VERSION рядом с движком: иной — движок не запускается.
	NFQWS   string `yaml:"nfqws"`
	LuaDir  string `yaml:"lua_dir"`
	Version string `yaml:"version"`
	// Dir — списки доменов движка: движок перечитывает их, уже сбросив
	// права root, — каталог должен быть доступен на чтение всем.
	Dir string `yaml:"dir"`
	// Debug — подробный журнал движка (dir/<канал>.debug.log); только для
	// разбора поломок.
	Debug bool `yaml:"debug"`
	// QueueBase — номер NFQUEUE первого канала; остальные идут подряд.
	QueueBase uint16 `yaml:"queue_base"`
	// Links — каналы с движком; пусто — все.
	Links           []model.LinkID `yaml:"links"`
	RecheckInterval time.Duration  `yaml:"recheck_interval"`
	ProbeDomains    []string       `yaml:"probe_domains"`
	// AllowRisks — какие рискованные стратегии подбирать (ts, syn); по
	// умолчанию — никаких.
	AllowRisks []coredpi.Risk `yaml:"allow_risks"`
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

// ApplyFlags применяет флаги -dry-run и -data-dir. Без явного -data-dir
// «сухой» запуск не создаёт файлов (база в памяти): на машине разработчика
// путь по умолчанию оказался бы в корне текущего диска.
func (c *Config) ApplyFlags(dryRun bool, dataDir string) {
	if dryRun {
		c.Daemon.DryRun = true
	}
	switch {
	case dataDir != "":
		c.SetDataDir(dataDir)
	case c.Daemon.DryRun:
		c.SetDataDir("")
	}
}

// SetDataDir подменяет daemon.data_dir (флаг -data-dir) вместе с выведенными
// из него умолчаниями; пустая строка — без каталога (база в памяти).
func (c *Config) SetDataDir(dir string) {
	if c.Proxy.WorkDir == defaultWorkDir(c.Daemon.DataDir) && dir != "" {
		c.Proxy.WorkDir = defaultWorkDir(dir)
	}
	c.Daemon.DataDir = dir
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
