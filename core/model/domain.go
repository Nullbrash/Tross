package model

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// NormalizeDomain приводит имя к виду, в котором оно хранится и сравнивается:
// нижний регистр, без завершающей точки. IDN-имена ожидаются уже в punycode.
func NormalizeDomain(s string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if d == "" {
		return "", errors.New("empty domain")
	}
	if len(d) > 253 {
		return "", fmt.Errorf("domain %q is longer than 253 bytes", d)
	}
	for label := range strings.SplitSeq(d, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("domain %q: bad label length", d)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
			if !ok {
				return "", fmt.Errorf("domain %q: invalid character %q", d, c)
			}
		}
	}
	return d, nil
}

// MatchKind — способ сопоставления шаблона доменного правила.
type MatchKind string

const (
	MatchExact MatchKind = "exact"
	// MatchSuffix — сам домен и все его поддомены (по границе метки).
	MatchSuffix  MatchKind = "suffix"
	MatchKeyword MatchKind = "keyword"
)

func (k MatchKind) Valid() bool {
	return k == MatchExact || k == MatchSuffix || k == MatchKeyword
}

// RuleLayer — слой списков; определяет приоритет правила.
type RuleLayer string

const (
	LayerManual  RuleLayer = "manual"
	LayerLearned RuleLayer = "learned"
	// LayerBuiltin — списки, поставляемые с Tross («никогда не трогать»):
	// проверены нами, поэтому важнее чужих онлайн-списков.
	LayerBuiltin RuleLayer = "builtin"
	LayerOnline  RuleLayer = "online"
)

// Rank — меньше значит важнее: ручные правила > выученные > встроенные >
// онлайн-списки.
func (l RuleLayer) Rank() int {
	switch l {
	case LayerManual:
		return 0
	case LayerLearned:
		return 1
	case LayerBuiltin:
		return 2
	case LayerOnline:
		return 3
	}
	return 100
}

// ListPurpose — что означает попадание домена в список.
type ListPurpose string

const (
	// PurposeBypass — кандидат на обход блокировки; метод (zapret на каком
	// канале или прокси) демон определяет проверкой.
	PurposeBypass ListPurpose = "bypass"
	// PurposeClass — домен относится к классу трафика (Class правила).
	PurposeClass ListPurpose = "class"
	// PurposeNever — не уводить в обход и прокси, не подменять: время,
	// STUN, игровые сети, проверки подключения, push.
	PurposeNever ListPurpose = "never"
	// PurposeInside — доступно только изнутри России: не уводить через
	// зарубежный выход.
	PurposeInside ListPurpose = "inside"
)

func (p ListPurpose) Valid() bool {
	return p == PurposeBypass || p == PurposeClass || p == PurposeNever || p == PurposeInside
}

func (l RuleLayer) Valid() bool { return l.Rank() < 100 }

// DomainRule — правило для домена. Пустой Method у онлайн-правила означает
// «кандидат»: способ обхода демон определяет проверкой и записывает в слой learned.
type DomainRule struct {
	Pattern string       `json:"pattern"`
	Match   MatchKind    `json:"match"`
	Layer   RuleLayer    `json:"layer"`
	Method  Method       `json:"method,omitempty"`
	Link    LinkID       `json:"link,omitempty"`
	ProxyID string       `json:"proxy_id,omitempty"`
	Class   TrafficClass `json:"class,omitempty"`
	// Purpose — вид правила; пусто — правило метода (Method) или класса.
	Purpose ListPurpose `json:"purpose,omitempty"`
	// Source — "user" или идентификатор источника списка.
	Source    string    `json:"source"`
	RecheckAt time.Time `json:"recheck_at,omitzero"`
}

func (r DomainRule) Validate() error {
	var errs []error
	if !r.Match.Valid() {
		errs = append(errs, fmt.Errorf("invalid match %q", r.Match))
	}
	if !r.Layer.Valid() {
		errs = append(errs, fmt.Errorf("invalid layer %q", r.Layer))
	}
	if r.Match == MatchKeyword {
		if r.Pattern == "" || r.Pattern != strings.ToLower(r.Pattern) {
			errs = append(errs, fmt.Errorf("keyword %q must be non-empty lowercase", r.Pattern))
		}
	} else if n, err := NormalizeDomain(r.Pattern); err != nil {
		errs = append(errs, err)
	} else if n != r.Pattern {
		errs = append(errs, fmt.Errorf("pattern %q is not normalized", r.Pattern))
	}
	if r.Method != "" && !r.Method.Final() {
		errs = append(errs, fmt.Errorf("invalid rule method %q", r.Method))
	}
	if r.Method == MethodProxy && r.ProxyID == "" {
		errs = append(errs, errors.New("proxy rule without proxy id"))
	}
	if r.Purpose != "" && !r.Purpose.Valid() {
		errs = append(errs, fmt.Errorf("invalid purpose %q", r.Purpose))
	}
	if r.Purpose == PurposeClass && r.Class == "" {
		errs = append(errs, errors.New("class rule without class"))
	}
	return errors.Join(errs...)
}

// Matches проверяет нормализованный домен на соответствие правилу.
func (r DomainRule) Matches(domain string) bool {
	switch r.Match {
	case MatchExact:
		return domain == r.Pattern
	case MatchSuffix:
		return domain == r.Pattern || strings.HasSuffix(domain, "."+r.Pattern)
	case MatchKeyword:
		return strings.Contains(domain, r.Pattern)
	}
	return false
}

// Precedes сообщает, важнее ли правило r правила o, если оба подходят к домену:
// сначала слой, затем точное совпадение, затем более длинный (конкретный) шаблон.
func (r DomainRule) Precedes(o DomainRule) bool {
	if r.Layer.Rank() != o.Layer.Rank() {
		return r.Layer.Rank() < o.Layer.Rank()
	}
	if a, b := matchSpecificity(r.Match), matchSpecificity(o.Match); a != b {
		return a > b
	}
	return len(r.Pattern) > len(o.Pattern)
}

func matchSpecificity(k MatchKind) int {
	switch k {
	case MatchExact:
		return 2
	case MatchSuffix:
		return 1
	}
	return 0
}
