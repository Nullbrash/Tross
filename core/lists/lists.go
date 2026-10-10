// Package lists — три слоя доменных списков (ручные → выученные → онлайн)
// и загрузка онлайн-источников (этап 4).
package lists

import (
	"context"
	"time"

	"tross/core/model"
)

// Format — формат онлайн-источника.
type Format string

const (
	FormatText    Format = "text"
	FormatGeosite Format = "geosite"
	FormatMRS     Format = "mrs"
)

func (f Format) Valid() bool { return f == FormatText || f == FormatGeosite || f == FormatMRS }

// Purpose — что означает попадание домена в список.
type Purpose string

const (
	// PurposeBypass — кандидат на обход блокировки; метод (zapret на каком
	// канале или прокси) демон определяет проверкой.
	PurposeBypass Purpose = "bypass"
	// PurposeClass — домен относится к классу трафика (например, streaming).
	PurposeClass Purpose = "class"
)

func (p Purpose) Valid() bool { return p == PurposeBypass || p == PurposeClass }

// Source — онлайн-источник списка доменов.
type Source struct {
	ID      string             `yaml:"id" json:"id"`
	URL     string             `yaml:"url" json:"url"`
	Format  Format             `yaml:"format" json:"format"`
	Purpose Purpose            `yaml:"purpose" json:"purpose"`
	Class   model.TrafficClass `yaml:"class" json:"class,omitempty"`
	// Categories — какие категории взять из geosite-файла.
	Categories []string `yaml:"categories" json:"categories,omitempty"`
	// Interval — свой период обновления; ноль — общий.
	Interval time.Duration `yaml:"interval" json:"interval,omitempty"`
}

// SourceStatus — состояние загрузки источника.
type SourceStatus struct {
	Source    Source    `json:"source"`
	Domains   int       `json:"domains"`
	UpdatedAt time.Time `json:"updated_at"`
	Error     string    `json:"error,omitempty"`
}

// ListManager хранит правила всех слоёв и отвечает на вопрос «что делать с доменом».
type ListManager interface {
	// Lookup возвращает самое приоритетное правило для нормализованного домена.
	Lookup(domain string) (model.DomainRule, bool)
	// Learn записывает результат собственной проверки демона (слой learned).
	Learn(rule model.DomainRule) error
	// SetManual заменяет ручные правила пользователя.
	SetManual(rules []model.DomainRule) error
	// Refresh загружает онлайн-источник заново; пустой id — все источники.
	Refresh(ctx context.Context, sourceID string) error
	Sources() []SourceStatus
}
