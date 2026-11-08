package daemon

import (
	"context"
	"fmt"
	"sync"

	"tross/core/classify"
	corelists "tross/core/lists"
	"tross/internal/config"
	"tross/internal/dataplane"
)

// reconfigurer меняет согласованный набор правил: сначала строит всё в
// памяти, затем атомарно меняет ядро и лишь после этого потребителей правил.
type reconfigurer struct {
	mu        sync.Mutex
	dp        dataplane.Dataplane
	binder    *deviceBinder
	dns       *dnsService
	explain   *explainer
	rules     *corelists.Rules
	classify  *classifierState
	spec      dataplane.Spec
	temporary []dataplane.PortForward
}

// classifierState даёт DNS и API один источник правды. Замена указателя
// происходит после успешной nft-транзакции, поэтому разные потребители не
// увидят разные наборы пользовательских правил.
type classifierState struct {
	mu  sync.RWMutex
	cls *classify.Engine
}

func newClassifierState(cls *classify.Engine) *classifierState { return &classifierState{cls: cls} }
func (s *classifierState) get() *classify.Engine               { s.mu.RLock(); defer s.mu.RUnlock(); return s.cls }
func (s *classifierState) replace(cls *classify.Engine)        { s.mu.Lock(); s.cls = cls; s.mu.Unlock() }

func (r *reconfigurer) Apply(ctx context.Context, cfg *config.Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.binder == nil {
		return fmt.Errorf("reconfigure: device binder is unavailable")
	}
	cat, err := serviceCatalog(cfg)
	if err != nil {
		return err
	}
	cls, err := newClassifier(cfg, cat, r.rules, r.binder.refs)
	if err != nil {
		return err
	}
	// Строим привязки кандидатной конфигурации без копирования mutex и без
	// мутации работающего binder.
	candidateBinder := &deviceBinder{cfg: cfg, reg: r.binder.reg}
	spec, err := dataplaneSpec(cfg, candidateBinder)
	if err != nil {
		return err
	}
	spec.Forwards = append(spec.Forwards, r.temporary...)
	if err := r.dp.ReplaceSpec(ctx, spec); err != nil {
		return err
	}
	r.spec = spec
	r.binder.replaceConfig(cfg)
	r.binder.changed()
	r.classify.replace(cls)
	return nil
}

// setTemporaryForwards заменяет только краткоживущие пробросы. Они не
// записываются в конфигурацию: после перезапуска порт остаётся закрытым.
func (r *reconfigurer) setTemporaryForwards(ctx context.Context, forwards []dataplane.PortForward) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	next := r.spec
	base := len(next.Forwards) - len(r.temporary)
	if base < 0 {
		return fmt.Errorf("reconfigure: temporary forward state is inconsistent")
	}
	next.Forwards = append(append([]dataplane.PortForward{}, next.Forwards[:base]...), forwards...)
	if err := r.dp.ReplaceSpec(ctx, next); err != nil {
		return err
	}
	r.spec, r.temporary = next, append([]dataplane.PortForward{}, forwards...)
	return nil
}
