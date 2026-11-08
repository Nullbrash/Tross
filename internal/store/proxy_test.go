package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"tross/core/proxypolicy"
)

func TestPolicyStore(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	v := proxypolicy.ListVersion{Source: "geosite", Version: "2026-11-09", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CheckedAt: now}
	if err := s.SavePolicyListVersion(ctx, v); err != nil {
		t.Fatal(err)
	}
	if got, err := s.PolicyListVersions(ctx); err != nil || len(got) != 1 || got[0].Source != v.Source || got[0].Version != v.Version || got[0].SHA256 != v.SHA256 || !got[0].CheckedAt.Equal(v.CheckedAt) {
		t.Fatalf("versions=%+v %v", got, err)
	}

	e := proxypolicy.TemporaryException{ID: "exc-1", Action: proxypolicy.ActionProxy, Match: proxypolicy.Match{DeviceID: "dev-1", Domain: "example.com"}, CreatedAt: now, ExpiresAt: now.Add(time.Hour), CreatedBy: "admin"}
	if err := s.SavePolicyException(ctx, e); err != nil {
		t.Fatal(err)
	}
	if got, err := s.PolicyExceptions(ctx, now); err != nil || len(got) != 1 || got[0].ID != e.ID {
		t.Fatalf("exceptions=%+v %v", got, err)
	}

	d := proxypolicy.Draft{Token: "opaque-token", Exception: e, ExpiresAt: now.Add(10 * time.Minute), ClusterID: "cluster-1", CreatedByKey: "key-id"}
	if err := s.SavePolicyDraft(ctx, d); err != nil {
		t.Fatal(err)
	}
	if got, err := s.PolicyDraft(ctx, d.Token, now); err != nil || got.Token != d.Token {
		t.Fatalf("draft=%+v %v", got, err)
	}
	if err := s.ConsumePolicyDraft(ctx, d.Token, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PolicyDraft(ctx, d.Token, now); !errors.Is(err, ErrNoDraft) {
		t.Fatalf("used draft: %v", err)
	}

	if err := s.AppendPolicyAudit(ctx, PolicyAudit{At: now, Topic: "exception.created", Data: []byte(`{"id":"exc-1"}`)}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.PolicyAudit(ctx, now.Add(-time.Second), 10); err != nil || len(got) != 1 || got[0].Topic != "exception.created" {
		t.Fatalf("audit=%+v %v", got, err)
	}
}
