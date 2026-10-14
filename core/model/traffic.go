package model

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// TrafficClass — класс трафика; задаёт политику выбора канала и метода.
// Строка, а не закрытое перечисление: набор классов расширяется конфигурацией,
// ниже — встроенные классы, которые знает классификатор.
type TrafficClass string

const (
	ClassDefault     TrafficClass = "default"
	ClassGaming      TrafficClass = "gaming"
	ClassVoIP        TrafficClass = "voip"
	ClassStreaming   TrafficClass = "streaming"
	ClassBulk        TrafficClass = "bulk"
	ClassIPSensitive TrafficClass = "ip_sensitive"
	ClassBroadcast   TrafficClass = "broadcast"
)

// BuiltinClasses — классы, которые классификатор умеет распознавать сам.
func BuiltinClasses() []TrafficClass {
	return []TrafficClass{ClassDefault, ClassGaming, ClassVoIP, ClassStreaming, ClassBulk, ClassIPSensitive, ClassBroadcast}
}

// Method — способ доставки соединения через выбранный канал.
type Method string

const (
	// MethodAuto допустим только в политике: метод определяется по спискам доменов.
	MethodAuto      Method = "auto"
	MethodDirect    Method = "direct"
	MethodDirectDPI Method = "direct_dpi"
	MethodProxy     Method = "proxy"
)

func (m Method) Valid() bool {
	switch m {
	case MethodAuto, MethodDirect, MethodDirectDPI, MethodProxy:
		return true
	}
	return false
}

// Final сообщает, может ли метод стоять в итоговом решении.
func (m Method) Final() bool { return m.Valid() && m != MethodAuto }

// Selector — как выбирать канал среди разрешённых политикой.
type Selector string

const (
	SelectLowestLatency  Selector = "lowest_latency"
	SelectBestThroughput Selector = "best_throughput"
	// SelectBestUpload — с наибольшей отдачей (свои трансляции).
	SelectBestUpload Selector = "best_upload"
	// SelectBalanced — распределение соединений по каналам с учётом их ёмкости.
	SelectBalanced Selector = "balanced"
	// SelectOrdered — первый пригодный канал в порядке списка Links.
	SelectOrdered Selector = "ordered"
)

func (s Selector) Valid() bool {
	switch s {
	case SelectLowestLatency, SelectBestThroughput, SelectBestUpload, SelectBalanced, SelectOrdered:
		return true
	}
	return false
}

// Stickiness — что закрепляется за каналом сверх самого соединения
// (отдельное соединение не переезжает никогда: его держит conntrack).
type Stickiness string

const (
	StickNone Stickiness = "none"
	// StickSession — все новые соединения устройства этого класса идут в тот же
	// канал, пока сессия активна (игра, звонок: один внешний IP для сервера).
	StickSession Stickiness = "session"
	// StickDestination — пара «устройство + домен/адрес» закреплена за каналом
	// надолго (банки, сервисы с капчей).
	StickDestination Stickiness = "destination"
	// StickService — все соединения устройства к одному сервису (все его
	// части) идут одним каналом: ссылки на видео YouTube подписаны внешним
	// адресом, с которого открыта страница.
	StickService Stickiness = "service"
)

func (s Stickiness) Valid() bool {
	return s == StickNone || s == StickSession || s == StickDestination || s == StickService
}

// Priority — приоритет трафика в очередях (CAKE diffserv, этап 3).
type Priority string

const (
	PriorityHigh   Priority = "high"
	PriorityNormal Priority = "normal"
	PriorityLow    Priority = "low"
)

func (p Priority) Valid() bool {
	return p == PriorityHigh || p == PriorityNormal || p == PriorityLow
}

// Policy — правила выбора канала и метода для класса трафика.
type Policy struct {
	Selector   Selector      `yaml:"selector" json:"selector"`
	Stickiness Stickiness    `yaml:"stickiness" json:"stickiness"`
	StickyTTL  time.Duration `yaml:"sticky_ttl" json:"sticky_ttl"`
	// Links — основной пул каналов; пусто — все каналы, кроме перечисленных в Fallback.
	Links []LinkID `yaml:"links" json:"links,omitempty"`
	// Fallback — каналы, используемые только когда ни один из Links не пригоден.
	// Канал, которого нет ни в Links, ни в Fallback (при непустом Links), для класса запрещён.
	Fallback   []LinkID `yaml:"fallback" json:"fallback,omitempty"`
	Method     Method   `yaml:"method" json:"method"`
	AllowProxy bool     `yaml:"allow_proxy" json:"allow_proxy"`
	Priority   Priority `yaml:"priority" json:"priority"`
}

// Validate проверяет внутреннюю согласованность политики (без сверки с реальными каналами).
func (p Policy) Validate() error {
	var errs []error
	if !p.Selector.Valid() {
		errs = append(errs, fmt.Errorf("invalid selector %q", p.Selector))
	}
	if !p.Stickiness.Valid() {
		errs = append(errs, fmt.Errorf("invalid stickiness %q", p.Stickiness))
	}
	if p.Stickiness != StickNone && p.StickyTTL <= 0 {
		errs = append(errs, errors.New("sticky_ttl must be positive when stickiness is set"))
	}
	if !p.Method.Valid() {
		errs = append(errs, fmt.Errorf("invalid method %q", p.Method))
	}
	if p.Method == MethodProxy && !p.AllowProxy {
		errs = append(errs, errors.New("method proxy requires allow_proxy"))
	}
	if !p.Priority.Valid() {
		errs = append(errs, fmt.Errorf("invalid priority %q", p.Priority))
	}
	for _, id := range p.Fallback {
		if slices.Contains(p.Links, id) {
			errs = append(errs, fmt.Errorf("link %q is both in links and fallback", id))
		}
	}
	return errors.Join(errs...)
}

// Protocol — транспортный протокол соединения.
type Protocol string

const (
	ProtoTCP Protocol = "tcp"
	ProtoUDP Protocol = "udp"
)

// Flow — новое соединение, для которого нужно принять решение.
type Flow struct {
	Proto    Protocol       `json:"proto"`
	Src      netip.AddrPort `json:"src"`
	Dst      netip.AddrPort `json:"dst"`
	SrcMAC   MAC            `json:"src_mac"`
	DeviceID string         `json:"device_id,omitempty"`
	// Domain — из DNS-сопоставления или SNI; может быть пустым.
	Domain string `json:"domain,omitempty"`
	// Signature — признак протокола по первому пакету с данными («stun»,
	// «discord_voice», «bittorrent»…); у UDP он есть до выбора канала, у TCP
	// первый пакет — SYN без данных, и признак приходит позже.
	Signature string `json:"signature,omitempty"`
}

// Key — устройство для закреплений: DeviceID, иначе адрес источника.
func (f Flow) Key() string {
	if f.DeviceID != "" {
		return f.DeviceID
	}
	return f.Src.Addr().String()
}

// Classification — результат работы классификатора.
type Classification struct {
	Class TrafficClass `json:"class"`
	// Confidence — от 0 до 1; низкая уверенность допускает переклассификацию.
	Confidence float64 `json:"confidence"`
	// Source — чем определён класс: "rule:…", "profile:сервис/часть",
	// "list:…", "default".
	Source string `json:"source"`
	// Service и Part — сервис и его часть из профиля (пусто — не из профиля).
	Service string `json:"service,omitempty"`
	Part    string `json:"part,omitempty"`
	// PinService — часть требует закрепления «устройство + сервис».
	PinService bool `json:"pin_service,omitempty"`
}

// Decision — итог движка решений для соединения: «канал + метод».
type Decision struct {
	Link    LinkID       `json:"link"`
	Method  Method       `json:"method"`
	ProxyID string       `json:"proxy_id,omitempty"`
	Class   TrafficClass `json:"class"`
	Sticky  bool         `json:"sticky"`
	// ExpiresAt — до какого момента действует закрепление; нулевое — без закрепления.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	Reason    string    `json:"reason,omitempty"`
}

func (d Decision) Validate() error {
	var errs []error
	if d.Link == "" {
		errs = append(errs, errors.New("decision without link"))
	}
	if !d.Method.Final() {
		errs = append(errs, fmt.Errorf("decision method %q is not final", d.Method))
	}
	if d.Method == MethodProxy && d.ProxyID == "" {
		errs = append(errs, errors.New("proxy decision without proxy id"))
	}
	if d.Method != MethodProxy && d.ProxyID != "" {
		errs = append(errs, errors.New("proxy id set for non-proxy decision"))
	}
	if d.Sticky && d.ExpiresAt.IsZero() {
		errs = append(errs, errors.New("sticky decision without expiry"))
	}
	return errors.Join(errs...)
}
