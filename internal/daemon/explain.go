package daemon

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"tross/core/classify"
	"tross/core/decision"
	"tross/core/model"
	"tross/core/profile"
	"tross/core/sqm"
	"tross/internal/api"
	"tross/internal/config"
	"tross/internal/dataplane"
)

// explainer отвечает «почему так»: классифицирует соединение тем же
// классификатором, по которому собраны правила ядра, и сверяется с тем,
// что ядро делает сейчас — план классов и закрепления берутся из ядра и
// балансировщика, а не из памяти движка (новые соединения он не видит).
type explainer struct {
	cls      *classify.Engine
	eng      *decision.Engine
	plan     func() []decision.ClassPlan
	dp       dataplane.Dataplane
	policies map[model.TrafficClass]model.Policy
}

func newExplainer(cfg *config.Config, cat profile.Catalog, bal *balancer, dp dataplane.Dataplane) (*explainer, error) {
	var rules []classify.Rule
	for _, r := range cfg.Classify.Rules {
		var devs []string
		for _, d := range r.Devices {
			devs = append(devs, d.String())
		}
		rules = append(rules, classify.Rule{Name: r.Name, Class: r.Class, Devices: devs, Match: r.Match})
	}
	// Доменных списков до резолвера (этап 4) нет.
	cls, err := classify.New(classify.Config{Rules: rules, Catalog: cat})
	if err != nil {
		return nil, err
	}
	return &explainer{cls: cls, eng: bal.engine, plan: bal.applied, dp: dp, policies: cfg.Policies()}, nil
}

func (x *explainer) explain(ctx context.Context, f model.Flow) (api.Explanation, error) {
	c := x.cls.Classify(f)
	ex := api.Explanation{Flow: f, Classification: c, Notes: inputNotes(f, c)}
	pol, ok := x.policies[c.Class]
	if !ok {
		pol = x.policies[model.ClassDefault]
		ex.Notes = append(ex.Notes, fmt.Sprintf("no policy for class %s: default policy applies", c.Class))
	}
	ex.Tin = sqm.TinFor(pol.Priority).String()

	var plan *decision.ClassPlan
	for _, p := range x.plan() {
		if p.Class == c.Class {
			plan = &p
			break
		}
	}
	if plan != nil {
		for _, s := range plan.Shares {
			ex.Shares = append(ex.Shares, api.ShareDTO{Link: s.Link, Weight: s.Weight})
		}
	}

	if d, err := x.eng.Explain(f, c, nil); err == nil {
		ex.Method = d.Method
	} else if !errors.Is(err, decision.ErrNoUsableLink) {
		return ex, err
	}

	kind, ttl := pinKind(c, pol)
	if kind != model.StickNone && plan != nil {
		pins, err := x.dp.Pins(ctx)
		if err != nil {
			return ex, err
		}
		if p, ok := findPin(pins, f, c, kind, plan.PinLinks); ok {
			ex.Pin = &api.PinDTO{Kind: kind, Link: p.Link, ExpiresS: int64(p.Expires.Seconds())}
			ex.Link = p.Link
			ex.Reason = fmt.Sprintf("pinned in kernel (%s), %s left", kind, p.Expires)
			return ex, nil
		}
	}

	switch {
	case plan == nil:
		ex.Reason = "no plan yet (links not probed): the kernel uses the first routed link by priority"
	case len(plan.Shares) == 0 && len(pol.Links) > 0:
		ex.Reason = "no usable link allowed for the class: the connection is rejected"
	case len(plan.Shares) == 0:
		ex.Reason = "no usable link: the connection goes by the main routing table"
	case len(plan.Shares) == 1:
		ex.Link = plan.Shares[0].Link
		ex.Reason = string(pol.Selector)
	default:
		ex.Reason = "split by weight: the kernel hashes device and destination address, the same pair keeps its link while weights hold"
	}
	if plan != nil && len(plan.Shares) > 0 && kind != model.StickNone {
		ex.Reason += fmt.Sprintf("; a new %s pin will hold the link for %s", kind, ttl)
	}
	return ex, nil
}

// pinKind — какое закрепление ставит ядро для класса (как renderPlan).
func pinKind(c model.Classification, pol model.Policy) (model.Stickiness, time.Duration) {
	if c.PinService && c.Service != "" {
		return model.StickService, cmp.Or(pol.StickyTTL, decision.DefaultServiceTTL)
	}
	if pol.Stickiness == model.StickSession || pol.Stickiness == model.StickDestination {
		if pol.StickyTTL > 0 {
			return pol.Stickiness, pol.StickyTTL
		}
	}
	return model.StickNone, 0
}

// findPin — закрепление ядра, под которое попадёт соединение; закрепления
// за каналами вне PinLinks ядро не применяет.
func findPin(pins []dataplane.Pin, f model.Flow, c model.Classification, kind model.Stickiness, links []model.LinkID) (dataplane.Pin, bool) {
	for _, p := range pins {
		if p.Device != f.Src.Addr() || !slices.Contains(links, p.Link) {
			continue
		}
		switch kind {
		case model.StickService:
			if p.Service == c.Service {
				return p, true
			}
		case model.StickSession:
			if p.Service == "" && p.Class == c.Class {
				return p, true
			}
		case model.StickDestination:
			if p.Service == "" && p.Class == c.Class && p.Dst == f.Dst.Addr() {
				return p, true
			}
		}
	}
	return dataplane.Pin{}, false
}

// inputNotes — честно о том, что из запроса ядро учтёт: в ядре нет доменов
// (только адреса из множеств, которые наполнит резолвер) и признаков TCP до
// первых данных.
func inputNotes(f model.Flow, c model.Classification) []string {
	var n []string
	if f.Domain != "" {
		n = append(n, "domain: the kernel matches only addresses the resolver put into the service's set (resolver comes in stage 4); until then only address and port count")
		if !f.Dst.Addr().IsValid() {
			n = append(n, "no dst: destination pins and existing connections are not checked")
		}
	}
	if f.Signature != "" {
		switch {
		case f.Proto == model.ProtoUDP:
			n = append(n, "signature: the kernel sees it in the first UDP packet")
		case f.Signature == "bittorrent":
			n = append(n, "signature: TCP BitTorrent shows after the handshake; the peer is remembered and later connections to it go to bulk")
		default:
			n = append(n, "signature: TCP signatures are not seen by the kernel before the link is chosen")
		}
	}
	if strings.HasPrefix(c.Source, "profile:") && c.Confidence < 1 {
		n = append(n, fmt.Sprintf("matched by %s (confidence %.2f)", c.Source, c.Confidence))
	}
	return n
}
