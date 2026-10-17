package dns

// Answer — ответ одного сервера в гонке.
type Answer struct {
	Upstream string
	// Empty — ответ без адресов (NXDOMAIN, нет записей): сервер с блокировкой
	// или отставший кэш отдаёт пустое там, где другой знает адрес.
	Empty bool
	Err   error
}

// Race — выбор ответа гонки: первый непустой побеждает сразу; пустой — только
// если непустого не будет; сбой — последним. Не потокобезопасен.
type Race struct {
	n, got     int
	empty, err *Answer
	winner     *Answer
}

func NewRace(n int) *Race { return &Race{n: n} }

// Offer — очередной ответ; true — гонка решена.
func (r *Race) Offer(a Answer) bool {
	if r.winner != nil {
		return true
	}
	r.got++
	switch {
	case a.Err != nil:
		if r.err == nil {
			r.err = &a
		}
	case a.Empty:
		if r.empty == nil {
			r.empty = &a
		}
	default:
		r.winner = &a
		return true
	}
	if r.got >= r.n {
		r.Settle()
		return true
	}
	return false
}

// Settle — ждать больше нельзя (тайм-аут): лучшее из пришедшего.
func (r *Race) Settle() {
	if r.winner == nil {
		r.winner = r.empty
	}
	if r.winner == nil {
		r.winner = r.err
	}
}

// Winner — решённый ответ; false — не пришло ничего.
func (r *Race) Winner() (Answer, bool) {
	if r.winner == nil {
		return Answer{}, false
	}
	return *r.winner, true
}
