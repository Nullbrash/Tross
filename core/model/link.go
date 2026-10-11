package model

import (
	"errors"
	"fmt"
	"time"
)

// LinkID — устойчивый идентификатор канала из конфигурации (например, "isp1").
// Используется в именах объектов nftables, поэтому формат ограничен (см. config).
type LinkID string

// LinkKind — физический тип канала.
type LinkKind string

const (
	LinkKindWired LinkKind = "wired"
	LinkKindLTE   LinkKind = "lte"
)

func (k LinkKind) Valid() bool { return k == LinkKindWired || k == LinkKindLTE }

// Link — статическое описание канала (из конфигурации).
type Link struct {
	ID        LinkID   `json:"id"`
	Name      string   `json:"name"`
	Kind      LinkKind `json:"kind"`
	Interface string   `json:"interface"`
	// Metered — трафик лимитирован: фоновые загрузки сюда не направляются.
	Metered bool `json:"metered"`
	// Priority — меньше значит предпочтительнее при прочих равных.
	Priority int `json:"priority"`
}

// LinkState — состояние канала после гистерезиса монитора.
type LinkState string

const (
	LinkStateUnknown  LinkState = "unknown"
	LinkStateUp       LinkState = "up"
	LinkStateDegraded LinkState = "degraded"
	LinkStateDown     LinkState = "down"
	// LinkStateRestricted — канал жив, но оператор пропускает только
	// «белый список» адресов; для общего трафика непригоден.
	LinkStateRestricted LinkState = "restricted"
)

func (s LinkState) Valid() bool {
	switch s {
	case LinkStateUnknown, LinkStateUp, LinkStateDegraded, LinkStateDown, LinkStateRestricted:
		return true
	}
	return false
}

// Usable сообщает, можно ли направлять в канал новые соединения общего назначения.
func (s LinkState) Usable() bool { return s == LinkStateUp || s == LinkStateDegraded }

// Throughput — измеренная (а не заявленная тарифом) пропускная способность.
type Throughput struct {
	DownBps    uint64    `json:"down_bps"`
	UpBps      uint64    `json:"up_bps"`
	MeasuredAt time.Time `json:"measured_at"`
}

// LinkHealth — текущее качество канала по активным проверкам.
type LinkHealth struct {
	LinkID     LinkID        `json:"link_id"`
	State      LinkState     `json:"state"`
	StateSince time.Time     `json:"state_since"`
	RTT        time.Duration `json:"rtt"`
	Jitter     time.Duration `json:"jitter"`
	// Loss — доля потерянных проб в окне, от 0 до 1.
	Loss       float64    `json:"loss"`
	Throughput Throughput `json:"throughput"`
	// RxBytes/TxBytes — накопительные счётчики интерфейса; обнуляются при
	// пересоздании интерфейса, поэтому потребитель считает разность с защитой.
	RxBytes   uint64    `json:"rx_bytes"`
	TxBytes   uint64    `json:"tx_bytes"`
	UpdatedAt time.Time `json:"updated_at"`
	Reason    string    `json:"reason,omitempty"`
}

func (h LinkHealth) Validate() error {
	var errs []error
	if h.LinkID == "" {
		errs = append(errs, errors.New("link id is empty"))
	}
	if !h.State.Valid() {
		errs = append(errs, fmt.Errorf("invalid state %q", h.State))
	}
	if h.RTT < 0 || h.Jitter < 0 {
		errs = append(errs, errors.New("negative rtt or jitter"))
	}
	if h.Loss < 0 || h.Loss > 1 {
		errs = append(errs, fmt.Errorf("loss %v out of [0,1]", h.Loss))
	}
	return errors.Join(errs...)
}

// LinkStatus — канал вместе с его текущим состоянием.
type LinkStatus struct {
	Link   Link       `json:"link"`
	Health LinkHealth `json:"health"`
}
