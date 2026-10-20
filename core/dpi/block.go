package dpi

import "time"

// Outcome — чем кончился шаг подключения.
type Outcome string

const (
	OK      Outcome = "ok"
	Timeout Outcome = "timeout"
	Reset   Outcome = "reset"
	Refused Outcome = "refused"
	// BadCert — ответил не тот сервер (подмена, страница провайдера).
	BadCert Outcome = "bad_cert"
)

// Attempt — одно подключение пробника: TCP, рукопожатие TLS, загрузка.
type Attempt struct {
	Connect   Outcome       `json:"connect"`
	Handshake Outcome       `json:"handshake,omitempty"`
	Received  int64         `json:"received"`
	Complete  bool          `json:"complete"`
	Elapsed   time.Duration `json:"elapsed"`
}

// Rate — байт в секунду загрузки (0 — нечего мерить).
func (a Attempt) Rate() float64 {
	if a.Received == 0 || a.Elapsed <= 0 {
		return 0
	}
	return float64(a.Received) / a.Elapsed.Seconds()
}

// BlockKind — что мешает домену на канале.
type BlockKind string

const (
	// KindNone — открывается напрямую.
	KindNone BlockKind = "none"
	// KindLinkBad — не открывается и контрольный домен: виноват канал, не DPI.
	KindLinkBad BlockKind = "link_bad"
	// KindIP — нет TCP до адреса: zapret бессилен.
	KindIP BlockKind = "ip"
	// KindSNI — обрыв или молчание после ClientHello: DPI по имени.
	KindSNI BlockKind = "sni"
	// KindIntercepted — отвечает не тот сервер.
	KindIntercepted BlockKind = "intercepted"
	// KindFreeze — передача встаёт после первых десятков КБ («заморозка»).
	KindFreeze BlockKind = "freeze"
	// KindThrottle — загрузка многократно медленнее контрольной.
	KindThrottle BlockKind = "throttle"
)

// Пороги классификации. Заморозка у ТСПУ — порядка 16–24 КБ (порядок
// величин, разнится по операторам); троттлинг — во много раз медленнее
// контрольной загрузки того же канала и на заметном объёме.
const (
	freezeMin       = 4 << 10
	freezeMax       = 64 << 10
	throttleRatio   = 5
	throttleMinSize = 256 << 10
)

// Classify — тип блокировки по попытке напрямую и контрольной попытке к
// незаблокированному домену через тот же канал.
func Classify(direct, control Attempt) BlockKind {
	if control.Connect != OK || control.Handshake != OK {
		return KindLinkBad
	}
	switch {
	case direct.Connect != OK:
		return KindIP
	case direct.Handshake == BadCert:
		return KindIntercepted
	case direct.Handshake != OK:
		return KindSNI
	case !direct.Complete && direct.Received >= freezeMin && direct.Received <= freezeMax:
		return KindFreeze
	case !direct.Complete:
		// Рукопожатие прошло, а данных нет или встали не там, где
		// заморозка: обрыв по имени после ClientHello сервера.
		return KindSNI
	case direct.Received >= throttleMinSize && control.Rate() > 0 && direct.Rate()*throttleRatio < control.Rate():
		return KindThrottle
	}
	return KindNone
}

// Helps — может ли стратегия движка помочь при такой блокировке.
func (k BlockKind) Helps() bool {
	switch k {
	case KindSNI, KindIntercepted, KindFreeze, KindThrottle:
		return true
	}
	return false
}
