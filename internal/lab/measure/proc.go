// Package measure — замеры ресурсов на стенде: разбор /proc и /sys, расчёт
// приращений между выборками. Используется утилитой cmd/labmeasure.
package measure

import "encoding/json"

// IfaceBytes — счётчики байт интерфейса.
type IfaceBytes struct {
	Name    string
	RxBytes uint64
	TxBytes uint64
}

// ParseIPLinkJSON разбирает вывод `ip -s -j link show`.
func ParseIPLinkJSON(b []byte) ([]IfaceBytes, error) {
	var links []struct {
		Ifname string `json:"ifname"`
		Stats  struct {
			Rx struct {
				Bytes uint64 `json:"bytes"`
			} `json:"rx"`
			Tx struct {
				Bytes uint64 `json:"bytes"`
			} `json:"tx"`
		} `json:"stats64"`
	}
	if err := json.Unmarshal(b, &links); err != nil {
		return nil, err
	}
	out := make([]IfaceBytes, 0, len(links))
	for _, l := range links {
		if l.Ifname == "lo" {
			continue
		}
		out = append(out, IfaceBytes{Name: l.Ifname, RxBytes: l.Stats.Rx.Bytes, TxBytes: l.Stats.Tx.Bytes})
	}
	return out, nil
}
