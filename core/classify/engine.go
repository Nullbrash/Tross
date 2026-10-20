package classify

import (
	"errors"
	"fmt"
	"slices"

	"tross/core/model"
	"tross/core/profile"
)

// Rule — правило пользователя: условие (как в профилях) и, по желанию,
// устройства (Flow.Key: ID устройства или адрес источника).
type Rule struct {
	Name    string
	Class   model.TrafficClass
	Devices []string
	Match   profile.Match
}

// DomainLookup — самое приоритетное доменное правило (слои списков).
type DomainLookup func(domain string) (model.DomainRule, bool)

type Config struct {
	Rules   []Rule
	Catalog profile.Catalog
	Domains DomainLookup // nil — без списков
	// Refs — все имена устройства-источника (адрес, id, MAC — как их пишут
	// Rule.Devices); nil — только Flow.Key.
	Refs func(model.Flow) []string
}

// Engine — классификатор. Порядок: правила пользователя → ручные доменные
// правила с классом → профили сервисов → выученные и онлайн-списки → default:
// своё важнее встроенного, встроенное — важнее чужих списков.
type Engine struct{ cfg Config }

var _ Classifier = (*Engine)(nil)

func New(cfg Config) (*Engine, error) {
	var errs []error
	for i, r := range cfg.Rules {
		if r.Class == "" {
			errs = append(errs, fmt.Errorf("rule %d (%s): no class", i, r.Name))
		}
		if err := r.Match.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("rule %d (%s): %w", i, r.Name, err))
		}
	}
	if err := cfg.Catalog.Validate(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &Engine{cfg: cfg}, nil
}

func (e *Engine) Classify(f model.Flow) model.Classification {
	var refs []string
	for _, r := range e.cfg.Rules {
		if len(r.Devices) > 0 && refs == nil {
			refs = []string{f.Key()}
			if e.cfg.Refs != nil {
				refs = append(refs, e.cfg.Refs(f)...)
			}
		}
		if (len(r.Devices) == 0 || slices.ContainsFunc(r.Devices, func(d string) bool { return slices.Contains(refs, d) })) && r.Match.Matches(f) {
			return model.Classification{Class: r.Class, Confidence: 1, Source: "rule:" + r.Name}
		}
	}
	var list *model.DomainRule
	if e.cfg.Domains != nil && f.Domain != "" {
		if d, err := model.NormalizeDomain(f.Domain); err == nil {
			if r, ok := e.cfg.Domains(d); ok && r.Class != "" {
				list = &r
			}
		}
	}
	if list != nil && list.Layer == model.LayerManual {
		return model.Classification{Class: list.Class, Confidence: 1, Source: "list:" + list.Source}
	}
	if h, ok := e.cfg.Catalog.Lookup(f); ok {
		return model.Classification{
			Class: h.Part.Class, Confidence: confidence[h.Basis()], Source: "profile:" + h.Service + "/" + h.Part.ID,
			Service: h.Service, Part: h.Part.ID, PinService: h.Part.PinService,
		}
	}
	if list != nil {
		return model.Classification{Class: list.Class, Confidence: 0.7, Source: "list:" + list.Source}
	}
	return model.Classification{Class: model.ClassDefault, Confidence: 0.1, Source: "default"}
}

// Уверенность по признаку: порт сам по себе — слабый признак, его делят многие.
var confidence = map[string]float64{"signature": 0.95, "domain": 0.9, "network": 0.8, "port": 0.6}
