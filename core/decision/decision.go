// Package decision — движок решений «канал + метод» (этап 2).
package decision

import (
	"errors"

	"tross/core/model"
)

// ErrNoUsableLink — ни один канал, разрешённый политикой класса, не пригоден.
var ErrNoUsableLink = errors.New("no usable link for traffic class")

// DecisionEngine выбирает канал и метод для соединения по политике его класса,
// текущему состоянию каналов и доменным правилам. Хранит закрепления
// (StickSession, StickDestination) и снимает их при падении канала.
type DecisionEngine interface {
	Decide(f model.Flow, c model.Classification, rule *model.DomainRule) (model.Decision, error)
	// UpdateLinks сообщает свежее состояние каналов (вызывается монитором).
	UpdateLinks(status []model.LinkStatus)
	// SetPolicies заменяет набор политик (при перечитывании конфигурации).
	SetPolicies(p map[model.TrafficClass]model.Policy) error
}
