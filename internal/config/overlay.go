package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"

	"tross/core/model"
)

// Overlay — правки интерфейса поверх файла конфигурации: только то, что
// правится в интерфейсе. Документ целиком (а не россыпь значений) — чтобы
// его можно было подписывать. Имена полей — как в YAML; документ — JSON
// (он же YAML) и разбирается так же строго, как файл.
type Overlay struct {
	// Links — правки каналов по id.
	Links map[model.LinkID]LinkOverlay `yaml:"links,omitempty"`
	// Forwards и ClassifyRules — заменяют разделы файла целиком.
	Forwards      *[]PortForward  `yaml:"forwards,omitempty"`
	ClassifyRules *[]ClassifyRule `yaml:"classify_rules,omitempty"`
}

type LinkOverlay struct {
	Priority *int `yaml:"priority,omitempty"`
	DownMbit *int `yaml:"down_mbit,omitempty"`
	UpMbit   *int `yaml:"up_mbit,omitempty"`
}

// Empty — правок нет.
func (o Overlay) Empty() bool {
	return len(o.Links) == 0 && o.Forwards == nil && o.ClassifyRules == nil
}

// ParseOverlay — строгий разбор документа правок.
func ParseOverlay(b []byte) (Overlay, error) {
	var o Overlay
	if len(bytes.TrimSpace(b)) == 0 {
		return o, nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&o); err != nil {
		return Overlay{}, fmt.Errorf("overlay: %w", err)
	}
	return o, nil
}

func (o Overlay) apply(c *Config) error {
	for id, lo := range o.Links {
		i := -1
		for j, l := range c.Links {
			if l.ID == id {
				i = j
			}
		}
		if i < 0 {
			return fmt.Errorf("overlay: link %q is not in the config file", id)
		}
		l := &c.Links[i]
		if lo.Priority != nil {
			l.Priority = *lo.Priority
		}
		if lo.DownMbit != nil {
			l.SQM.DownMbit = *lo.DownMbit
		}
		if lo.UpMbit != nil {
			l.SQM.UpMbit = *lo.UpMbit
		}
	}
	if o.Forwards != nil {
		c.Inbound.Forwards = *o.Forwards
	}
	if o.ClassifyRules != nil {
		c.Classify.Rules = *o.ClassifyRules
	}
	return nil
}

// ParseWithOverlay — файл + правки, затем умолчания и та же проверка, что
// у файла.
func ParseWithOverlay(file []byte, o Overlay) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(file))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := o.apply(&cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func LoadWithOverlay(path string, o Overlay) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := ParseWithOverlay(data, o)
	if err != nil {
		return nil, fmt.Errorf("%s + interface changes: %w", path, err)
	}
	return cfg, nil
}

// FileSections — то, что правится в интерфейсе, как в файле (JSON с именами
// полей YAML): интерфейс показывает «в файле было …».
func FileSections(c *Config) (json.RawMessage, error) {
	links := map[model.LinkID]LinkOverlay{}
	for _, l := range c.Links {
		p, d, u := l.Priority, l.SQM.DownMbit, l.SQM.UpMbit
		links[l.ID] = LinkOverlay{Priority: &p, DownMbit: &d, UpMbit: &u}
	}
	f, r := c.Inbound.Forwards, c.Classify.Rules
	return ToJSON(Overlay{Links: links, Forwards: &f, ClassifyRules: &r})
}

// ToJSON — значение с тегами yaml в JSON с теми же именами полей.
func ToJSON(v any) (json.RawMessage, error) {
	y, err := yaml.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m any
	if err := yaml.Unmarshal(y, &m); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}
