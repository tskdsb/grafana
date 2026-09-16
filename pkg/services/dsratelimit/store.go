package dsratelimit

import (
	"context"
	"time"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/sqlstore"
)

// store is the internal persistence layer for rate-limit rules.
// It is intentionally minimal: rules are read on startup and refreshed
// periodically; the middleware never touches the DB on the hot path.
type store struct {
	db     db.DB
	logger log.Logger
}

func newStore(dbConn db.DB) *store {
	return &store{
		db:     dbConn,
		logger: log.New("dsratelimit.store"),
	}
}

// list returns every rule. Called on startup and each reload tick.
func (s *store) list(ctx context.Context) ([]Rule, error) {
	rules := make([]Rule, 0)
	err := s.db.WithDbSession(ctx, func(sess *sqlstore.DBSession) error {
		return sess.Find(&rules)
	})
	return rules, err
}

// get returns the rule keyed by (kind, target), or nil if none exists.
func (s *store) get(ctx context.Context, kind, target string) (*Rule, error) {
	var r Rule
	var found bool
	err := s.db.WithDbSession(ctx, func(sess *sqlstore.DBSession) error {
		has, err := sess.Where("kind = ? AND target = ?", kind, target).Get(&r)
		if err != nil {
			return err
		}
		found = has
		return nil
	})
	if err != nil || !found {
		return nil, err
	}
	return &r, nil
}

// upsert creates or updates a rule keyed by (kind, target).
// The `updated` column is always set to now; `created` is preserved on update.
func (s *store) upsert(ctx context.Context, r *Rule) error {
	return s.db.WithTransactionalDbSession(ctx, func(sess *sqlstore.DBSession) error {
		var existing Rule
		has, err := sess.Where("kind = ? AND target = ?", r.Kind, r.Target).Get(&existing)
		if err != nil {
			return err
		}
		now := time.Now()
		r.Updated = now
		if !has {
			r.Created = now
			_, err := sess.Insert(r)
			return err
		}
		r.Id = existing.Id
		r.Created = existing.Created
		_, err = sess.ID(existing.Id).AllCols().Update(r)
		return err
	})
}

// delete removes a rule keyed by (kind, target). No error when not found.
func (s *store) delete(ctx context.Context, kind, target string) error {
	return s.db.WithTransactionalDbSession(ctx, func(sess *sqlstore.DBSession) error {
		_, err := sess.Where("kind = ? AND target = ?", kind, target).Delete(&Rule{})
		return err
	})
}
