// Package linkmon — монитор каналов: активные проверки задержки, джиттера и
// потерь через каждый канал, измерение пропускной способности, гистерезис
// состояний, распознавание режима «белых списков» на LTE (этап 1).
package linkmon

import (
	"context"

	"tross/core/model"
)

// LinkMonitor следит за каналами и публикует смены состояния в шину событий
// (event.TopicLinkState).
type LinkMonitor interface {
	// Run выполняет проверки до отмены ctx.
	Run(ctx context.Context) error
	// Snapshot — состояние всех каналов в порядке конфигурации.
	Snapshot() []model.LinkStatus
	Status(id model.LinkID) (model.LinkStatus, bool)
}
