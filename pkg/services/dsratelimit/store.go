package dsratelimit

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
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

// ErrInvalidMergedRule reports a merge that produced a rule which must not be
// stored -- raised inside the write transaction, after the merge against the
// locked row, so it catches pairs no single request asked for.
type ErrInvalidMergedRule struct{ Reason string }

func (e *ErrInvalidMergedRule) Error() string { return e.Reason }

// The (kind, target) write path, and what each database contributes to it.
//
// Both writers below read the row under FOR UPDATE before writing it. The read
// is not decoration in upsertPartial's case -- it is where the merge happens,
// so a field the request did not mention keeps whatever is actually stored
// rather than whatever the handler saw a moment earlier.
//
//	SQLite      serialises write transactions itself, and takes a table lock
//	            doing so -- concurrent writers here surface as "table is
//	            locked", which is why upsertPartial retries. ForUpdate() is a
//	            no-op: xorm's sqlite3 dialect returns the query unchanged
//	            (xorm@v0.8.2 dialect_sqlite3.go:247).
//	MySQL, PG   core.Base appends FOR UPDATE (core@v0.7.2 dialect.go:292) and
//	            the row lock is what serialises two writers to one rule.
//	            Contention is far rarer than on SQLite, and the retry is
//	            harmless when it does not happen.
//
// So the row lock is reasoned from the dialect source rather than verified: the
// tests run on SQLite, where it is absent and the table lock does the work.
// What the tests do verify is the merge-under-lock behaviour, which is
// observable on either database because it needs two overlapping requests, not
// two overlapping transactions.

// upsertPartial applies a partial update inside the row lock.
//
// The merge happens here, after FOR UPDATE, and not in the handler. That is the
// whole point: a value computed from a snapshot read outside the transaction is
// already stale by the time it is written, so two writers each changing a
// different field would both succeed and the second would silently revert the
// first. Measured on the earlier handler-merge version: 17 of 20 concurrent
// rounds lost one of the two changes, both requests returning 200.
//
// The handler still merges once beforehand -- it has to, since validation needs
// to judge the rule as it will be stored -- but that result is advisory. What
// lands is computed from the row this transaction locked.
func (s *store) upsertPartial(ctx context.Context, kind, target, mode string,
	actorID *int64, rate, burst, conc fieldUpdate,
	validate func(rate, burst, conc *int64) string) (*Rule, error) {
	// Retried on lock contention rather than surfaced. Two admins editing one
	// rule at once is a normal thing to do, and "the table was busy" is not
	// something the caller can act on -- they would simply reissue the request.
	//
	// The budget is deliberately generous. SQLite takes a *table* lock, so any
	// two concurrent writes to this table contend, and under -race the extra
	// scheduling latency made five attempts with a 5ms step run out on roughly
	// one run in six. MySQL takes a row lock and contends far less, but the
	// same budget costs nothing there and covers a slow lock wait.
	//
	// Still bounded: a lock held by something other than a peer write is a real
	// fault, and spinning forever would turn it into a hung request.
	const (
		attempts = 12
		baseWait = 4 * time.Millisecond
	)
	var (
		written *Rule
		err     error
	)
	for attempt := 0; attempt < attempts; attempt++ {
		written, err = s.upsertPartialOnce(ctx, kind, target, mode, actorID,
			rate, burst, conc, validate)
		if err == nil || !isLockContention(err) {
			return written, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Linear backoff with jitter. Without the jitter two writers that
		// collided once tend to keep colliding, since they retry in lockstep.
		wait := baseWait * time.Duration(attempt+1)
		time.Sleep(wait + time.Duration(rand.Int63n(int64(baseWait))))
	}
	// Exhausted. Reported as such rather than as the raw driver error, so the
	// operator knows retrying by hand is reasonable.
	return nil, fmt.Errorf(
		"the rule was locked by another write for %d attempts; retry: %w", attempts, err)
}

// isLockContention reports a transient "someone else is writing" error, as
// opposed to a rejection or a genuine failure.
func isLockContention(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "locked") ||
		strings.Contains(msg, "database is busy") ||
		strings.Contains(msg, "deadlock") ||
		strings.Contains(msg, "lock wait timeout")
}

func (s *store) upsertPartialOnce(ctx context.Context, kind, target, mode string,
	actorID *int64, rate, burst, conc fieldUpdate,
	validate func(rate, burst, conc *int64) string) (*Rule, error) {
	var written *Rule
	err := s.db.WithTransactionalDbSession(ctx, func(sess *sqlstore.DBSession) error {
		var existing Rule
		has, err := sess.Where("kind = ? AND target = ?", kind, target).
			ForUpdate().Get(&existing)
		if err != nil {
			// A failed read must not fall through to a write: every absent
			// field would be treated as "nothing stored" and cleared.
			return err
		}
		now := time.Now()
		r := &Rule{
			Kind: kind, Target: target, Mode: mode,
			UpdatedBy: actorID, Updated: now,
		}
		if !has {
			r.Rate = rate.apply(nil)
			r.Burst = burst.apply(nil)
			r.Concurrency = conc.apply(nil)
			if msg := validate(r.Rate, r.Burst, r.Concurrency); msg != "" {
				return &ErrInvalidMergedRule{Reason: msg}
			}
			r.Created = now
			if _, err := sess.Insert(r); err != nil {
				return err
			}
			written = r
			return nil
		}
		// Re-applied against the locked row, so a field this request did not
		// mention keeps whatever a concurrent write left there.
		r.Rate = rate.apply(existing.Rate)
		r.Burst = burst.apply(existing.Burst)
		r.Concurrency = conc.apply(existing.Concurrency)
		// Validated here, not only in the handler. The handler judged the row as
		// it was before the lock; this judges what will actually be stored. Two
		// requests each changing one half of the QPS pair can merge, in
		// sequence, into a pair neither of them asked for -- returning the error
		// rolls the transaction back rather than storing it.
		if msg := validate(r.Rate, r.Burst, r.Concurrency); msg != "" {
			return &ErrInvalidMergedRule{Reason: msg}
		}
		r.Id = existing.Id
		r.Created = existing.Created
		if _, err := sess.ID(existing.Id).AllCols().Update(r); err != nil {
			return err
		}
		// Returned so the caller logs and echoes what actually landed, not the
		// advisory merge it computed from a snapshot.
		written = r
		return nil
	})
	return written, err
}

// upsert writes a rule wholesale, with no merge and no validation.
//
// NOT a write path for the admin API -- nothing in production calls it, and
// nothing should. Every operator-facing write goes through upsertPartial, which
// merges against the locked row and validates the result; going around it is
// how invalid pairs and lost updates got in twice during review.
//
// It stays because tests need a cheap way to seed "the table already contains
// this rule" without driving a request through the handler. Keep it to that.
func (s *store) upsert(ctx context.Context, r *Rule) error {
	return s.db.WithTransactionalDbSession(ctx, func(sess *sqlstore.DBSession) error {
		var existing Rule
		has, err := sess.Where("kind = ? AND target = ?", r.Kind, r.Target).
			ForUpdate().Get(&existing)
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
