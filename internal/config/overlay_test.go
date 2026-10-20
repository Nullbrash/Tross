package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOverlay(t *testing.T) {
	file := []byte(minimal + "links:\n  - { id: isp1, kind: wired, interface: eth1, priority: 1, sqm: { enabled: true, down_mbit: 100, up_mbit: 20 } }\n  - { id: lte, kind: lte, interface: eth2 }\n")
	// minimal уже содержит links — берём файл без них.
	file = []byte(strings.Replace(string(file), "links:\n  - { id: isp1, kind: wired, interface: eth1 }\n  - { id: lte, kind: lte, interface: eth2 }\n", "", 1))
	o, err := ParseOverlay([]byte(`{"links":{"isp1":{"priority":5,"down_mbit":300}},"forwards":[{"name":"mc","port":25565,"to":"a6:00:00:00:00:01"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseWithOverlay(file, o)
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.Links[0]
	if l.Priority != 5 || l.SQM.DownMbit != 300 || l.SQM.UpMbit != 20 || len(cfg.Inbound.Forwards) != 1 || cfg.Inbound.Forwards[0].Proto != "tcp" {
		t.Fatalf("merged: %+v %+v", l, cfg.Inbound.Forwards)
	}
	// Правки проверяются как файл.
	for name, doc := range map[string]string{
		"unknown field":  `{"lnks":{}}`,
		"unknown link":   `{"links":{"isp9":{"priority":1}}}`,
		"bad forward":    `{"forwards":[{"name":"x","port":0,"to":"192.168.1.5"}]}`,
		"bad device ref": `{"classify_rules":[{"name":"x","class":"default","devices":["tv"],"ports":["1"]}]}`,
	} {
		o, err := ParseOverlay([]byte(doc))
		if err == nil {
			_, err = ParseWithOverlay(file, o)
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if o, _ := ParseOverlay([]byte(`{}`)); !o.Empty() {
		t.Error("empty overlay")
	}
	// Как в файле — JSON с именами YAML.
	fs, err := FileSections(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if json.Unmarshal(fs, &m) != nil || m["links"] == nil || !strings.Contains(string(fs), `"down_mbit":300`) {
		t.Errorf("file sections %s", fs)
	}
}
