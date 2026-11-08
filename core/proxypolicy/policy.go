// Package proxypolicy содержит независимую от Linux модель выбора способа
// доставки. Исполнитель nftables/TProxy подключается в следующих фазах.
package proxypolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"tross/core/model"
)

// Action — терминальный результат proxy-политики до выбора канала.
type Action string

const (
	ActionBlock  Action = "block"
	ActionProxy  Action = "proxy"
	ActionDirect Action = "direct"
)

func (a Action) Valid() bool {
	return a == ActionBlock || a == ActionProxy || a == ActionDirect
}

// Stage задаёт фиксированный порядок правил, а не порядок строк во входном
// бэкапе. Это не позволяет случайно выпустить proxy-назначение напрямую.
type Stage string

const (
	StageSystem    Stage = "system"
	StageBlock     Stage = "block"
	StageException Stage = "exception"
	StageProxy     Stage = "proxy"
	StageDirect    Stage = "direct"
	StageGeoIPRU   Stage = "geoip_ru"
	StageGeoSiteRU Stage = "geosite_ru"
	StageACL       Stage = "acl"
	StageDefault   Stage = "default"
)

func (s Stage) rank() int {
	switch s {
	case StageSystem:
		return 0
	case StageBlock:
		return 1
	case StageException:
		return 2
	case StageProxy:
		return 3
	case StageDirect:
		return 4
	case StageGeoIPRU:
		return 5
	case StageGeoSiteRU:
		return 6
	case StageACL:
		return 7
	case StageDefault:
		return 8
	}
	return 99
}

func (s Stage) Valid() bool { return s.rank() < 99 }

// Flow — нормализованный сетевой контекст. Имя процесса намеренно отсутствует:
// шлюз его не получает из пакета.
type Flow struct {
	DeviceID string
	Domain   string
	IP       netip.Addr
	Port     uint16
	Protocol model.Protocol
	GeoIP    map[string]bool
	GeoSite  map[string]bool
	ACL      map[string]bool
}

// Match — сетевые условия одного правила. Непустые поля объединяются через И.
type Match struct {
	DeviceID string
	Domain   string
	IP       netip.Addr
	Port     uint16
	Protocol model.Protocol
	ACL      string
	GeoIP    string
	GeoSite  string
}

func (m Match) matches(f Flow) bool {
	if m.DeviceID != "" && m.DeviceID != f.DeviceID {
		return false
	}
	if m.Domain != "" && m.Domain != f.Domain {
		return false
	}
	if m.IP.IsValid() && m.IP != f.IP {
		return false
	}
	if m.Port != 0 && m.Port != f.Port {
		return false
	}
	if m.Protocol != "" && m.Protocol != f.Protocol {
		return false
	}
	if m.ACL != "" && !f.ACL[m.ACL] {
		return false
	}
	if m.GeoIP != "" && !f.GeoIP[m.GeoIP] {
		return false
	}
	return m.GeoSite == "" || f.GeoSite[m.GeoSite]
}

// Rule — правило в одной из упорядоченных стадий.
type Rule struct {
	ID     string
	Stage  Stage
	Action Action
	Match  Match
	// AllowBlockOverride применимо только к пользовательскому постоянному block.
	// Системные блокировки всегда неотменяемы.
	AllowBlockOverride bool
}

func (r Rule) Validate() error {
	if r.ID == "" {
		return errors.New("policy rule without id")
	}
	if !r.Stage.Valid() {
		return fmt.Errorf("policy rule %q: invalid stage %q", r.ID, r.Stage)
	}
	if !r.Action.Valid() {
		return fmt.Errorf("policy rule %q: invalid action %q", r.ID, r.Action)
	}
	if r.Stage == StageSystem && r.Action != ActionBlock {
		return fmt.Errorf("policy rule %q: system stage must block", r.ID)
	}
	if r.Stage == StageDefault && (r.Action != ActionProxy || !r.Match.matches(Flow{})) {
		return fmt.Errorf("policy rule %q: default must be unconditional proxy", r.ID)
	}
	if r.Match.Domain != "" {
		d, err := model.NormalizeDomain(r.Match.Domain)
		if err != nil {
			return fmt.Errorf("policy rule %q: %w", r.ID, err)
		}
		if d != r.Match.Domain {
			return fmt.Errorf("policy rule %q: domain is not normalized", r.ID)
		}
	}
	return nil
}

// TemporaryException — подтверждённое узкое правило. Хранилище и API будут
// подключены отдельно; эта модель не создаёт исключения сама.
type TemporaryException struct {
	ID        string
	Action    Action
	Match     Match
	CreatedAt time.Time
	ExpiresAt time.Time
	CreatedBy string
	AuditNote string
}

func (e TemporaryException) Active(at time.Time) bool {
	return !e.ExpiresAt.IsZero() && at.Before(e.ExpiresAt)
}

func (e TemporaryException) Validate() error {
	if e.ID == "" || e.CreatedBy == "" {
		return errors.New("exception requires id and creator")
	}
	if !e.Action.Valid() || e.Action == ActionBlock {
		return errors.New("exception must select direct or proxy")
	}
	if e.ExpiresAt.IsZero() || !e.ExpiresAt.After(e.CreatedAt) {
		return errors.New("exception expiry must be after creation")
	}
	if e.Match.DeviceID == "" && e.Match.Domain == "" && !e.Match.IP.IsValid() {
		return errors.New("exception must be scoped to device, domain, or IP")
	}
	return nil
}

// Draft — предложение для будущего подтверждаемого интерфейса. Token не
// содержит правило и должен быть непрозрачным случайным идентификатором.
type Draft struct {
	Token        string
	Exception    TemporaryException
	ExpiresAt    time.Time
	ClusterID    string
	CreatedByKey string
}

func (d Draft) Validate(now time.Time) error {
	if strings.TrimSpace(d.Token) == "" || strings.TrimSpace(d.ClusterID) == "" || strings.TrimSpace(d.CreatedByKey) == "" {
		return errors.New("draft requires token, cluster, and key id")
	}
	if !d.ExpiresAt.After(now) {
		return errors.New("draft is expired")
	}
	return d.Exception.Validate()
}

// ListVersion позволяет загрузчику опубликовать только проверенный снимок.
// Содержимое списка здесь намеренно не хранится.
type ListVersion struct {
	Source    string
	Version   string
	SHA256    string
	CheckedAt time.Time
}

func (v ListVersion) Validate() error {
	if strings.TrimSpace(v.Source) == "" || strings.TrimSpace(v.Version) == "" {
		return errors.New("list version requires source and version")
	}
	if len(v.SHA256) != 64 {
		return errors.New("list version requires sha256")
	}
	for _, c := range v.SHA256 {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return errors.New("list sha256 must be lowercase hexadecimal")
		}
	}
	if v.CheckedAt.IsZero() {
		return errors.New("list version requires check time")
	}
	return nil
}

// Decision объясняет совпавшее правило, что нужно для журнала и будущего UI.
type Decision struct {
	Action Action
	RuleID string
	Stage  Stage
}

// Decide применяет системные блокировки, затем активные исключения и обычный
// фиксированный порядок. Исключение не может преодолеть системную блокировку.
func Decide(flow Flow, rules []Rule, exceptions []TemporaryException, now time.Time) (Decision, error) {
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return Decision{}, err
		}
	}
	for _, r := range rules {
		if r.Stage == StageSystem && r.Match.matches(flow) {
			return Decision{Action: ActionBlock, RuleID: r.ID, Stage: r.Stage}, nil
		}
	}
	for _, e := range exceptions {
		if err := e.Validate(); err != nil {
			return Decision{}, err
		}
		if e.Active(now) && e.Match.matches(flow) {
			return Decision{Action: e.Action, RuleID: e.ID, Stage: StageException}, nil
		}
	}
	for rank := 1; rank <= 8; rank++ {
		for _, r := range rules {
			if r.Stage.rank() == rank && r.Match.matches(flow) {
				return Decision{Action: r.Action, RuleID: r.ID, Stage: r.Stage}, nil
			}
		}
	}
	return Decision{}, errors.New("proxy policy has no matching default")
}
