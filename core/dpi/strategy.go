// Package dpi — логика обхода DPI без Linux: стратегии движка (nfqws2) как
// данные, тип блокировки по наблюдениям пробника, решение «как открывать
// домен на канале», порядок стратегий канала, пределы частоты проверок.
// Запуск движка, правила ядра и сам пробник — в internal/.
package dpi

import (
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Risk — свойство стратегии, из-за которого она по умолчанию не
// подбирается автоматически.
type Risk string

const (
	// RiskTS — фейк держится на TCP timestamps: их согласует ОС устройства,
	// а у Windows они выключены — фейк дойдёт до сервера живым и сломает
	// соединение.
	RiskTS Risk = "ts"
	// RiskSYN — приёмы фазы рукопожатия (wssize, syndata): в доменной схеме
	// имя ещё неизвестно, а через NAT они ломают соединения.
	RiskSYN Risk = "syn"
)

// Strategy — одна стратегия: последовательность вызовов --lua-desync для
// профиля движка (полезная нагрузка Payload). Аргументы целиком (фильтры,
// hostlist, очередь) собирает internal/dpi.
type Strategy struct {
	ID      string `yaml:"id" json:"id"`
	Payload string `yaml:"payload" json:"payload"`
	// Steps — значения --lua-desync по порядку (fake, затем split и т. п.).
	Steps []string `yaml:"steps" json:"steps"`
	Note  string   `yaml:"note" json:"note,omitempty"`
}

var (
	idRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	stepRe = regexp.MustCompile(`^[a-z_]+(:[A-Za-z0-9_=,.+#-]+)*$`)
)

// Validate — форма, а не смысл: что движок примет аргументы, проверяет
// пробный запуск движка (internal/dpi).
func (s Strategy) Validate() error {
	var errs []error
	if !idRe.MatchString(s.ID) {
		errs = append(errs, fmt.Errorf("id %q: want lowercase letters, digits, '-'", s.ID))
	}
	if s.Payload == "" {
		errs = append(errs, errors.New("payload is empty"))
	}
	if len(s.Steps) == 0 {
		errs = append(errs, errors.New("no steps"))
	}
	for _, st := range s.Steps {
		switch {
		case !stepRe.MatchString(st):
			errs = append(errs, fmt.Errorf("step %q: want func[:arg=value…]", st))
		case stepFunc(st) == "luaexec":
			// Произвольный Lua-код в движке с правами root — не стратегия.
			errs = append(errs, fmt.Errorf("step %q: luaexec is not allowed", st))
		}
	}
	return errors.Join(errs...)
}

// stepFunc — имя функции шага («fake», «multisplit»).
func stepFunc(step string) string {
	f, _, _ := strings.Cut(step, ":")
	return f
}

// Risks — по шагам: аргументы tcp_ts* — RiskTS, функции фазы SYN — RiskSYN.
func (s Strategy) Risks() []Risk {
	var out []Risk
	for _, st := range s.Steps {
		if strings.Contains(st, ":tcp_ts") {
			out = append(out, RiskTS)
		}
		switch stepFunc(st) {
		case "wssize", "syndata":
			out = append(out, RiskSYN)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Args — аргументы движка для профиля стратегии (без фильтров профиля).
func (s Strategy) Args() []string {
	out := []string{"--payload=" + s.Payload}
	for _, st := range s.Steps {
		out = append(out, "--lua-desync="+st)
	}
	return out
}

//go:embed catalog.yaml
var builtin []byte

// Catalog — кандидаты для автоподбора; Engine — версия движка, под которую
// записаны аргументы (между версиями формат меняется).
type Catalog struct {
	Engine     string     `yaml:"engine"`
	Strategies []Strategy `yaml:"strategies"`
}

func Builtin() (Catalog, error) { return ParseCatalog(builtin) }

func ParseCatalog(b []byte) (Catalog, error) {
	var c Catalog
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Catalog{}, err
	}
	return c, c.Validate()
}

func (c Catalog) Validate() error {
	var errs []error
	if c.Engine == "" {
		errs = append(errs, errors.New("catalog: engine is empty"))
	}
	seen := map[string]bool{}
	for i, s := range c.Strategies {
		if err := s.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("strategy %d: %w", i, err))
		}
		if seen[s.ID] {
			errs = append(errs, fmt.Errorf("strategy %q: duplicate id", s.ID))
		}
		seen[s.ID] = true
	}
	return errors.Join(errs...)
}

// Candidates — стратегии для автоподбора: без рисков, кроме разрешённых.
func (c Catalog) Candidates(allow ...Risk) []Strategy {
	var out []Strategy
	for _, s := range c.Strategies {
		ok := true
		for _, r := range s.Risks() {
			ok = ok && slices.Contains(allow, r)
		}
		if ok {
			out = append(out, s)
		}
	}
	return out
}

// ByID — стратегия каталога.
func (c Catalog) ByID(id string) (Strategy, bool) {
	i := slices.IndexFunc(c.Strategies, func(s Strategy) bool { return s.ID == id })
	if i < 0 {
		return Strategy{}, false
	}
	return c.Strategies[i], true
}
