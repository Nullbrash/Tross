// Package classify — определение класса трафика для соединения (этап 2).
package classify

import "tross/core/model"

// Classifier относит новое соединение к классу трафика по портам, домену,
// устройству и пользовательским правилам. Должен быть быстрым и без
// блокирующих операций: вызывается на каждое новое соединение.
type Classifier interface {
	Classify(f model.Flow) model.Classification
}
