package dsratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/services/sqlstore"
)

// TestIntegrationDsRateLimitStore exercises the CRUD surface end-to-end
// against the migrated schema: the migration in
// pkg/services/sqlstore/migrations/ds_ratelimit_mig.go runs cleanly and CRUD
// works against the result.
func TestIntegrationDsRateLimitStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ss := db.InitTestDB(t)
	s := newStore(ss)
	ctx := context.Background()

	rate50 := int64(50)
	burst := int64(100)

	t.Run("upsert then get", func(t *testing.T) {
		require.NoError(t, s.upsert(ctx, &Rule{
			Kind: "sa", Target: "12", Mode: "limited", Rate: &rate50, Burst: &burst,
		}))
		got, err := s.get(ctx, "sa", "12")
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, "limited", got.Mode)
		require.Equal(t, int64(50), *got.Rate)
	})

	t.Run("upsert writes the row exactly as given", func(t *testing.T) {
		// store.upsert is the plain write: whatever Rule it receives is what
		// the row becomes, nil fields included. Merging a partial body with the
		// stored row happens in AdminPut, which needs the old values to
		// validate against anyway -- doing it again here would mean two places
		// deciding what "omitted" means.
		newRate := int64(80)
		require.NoError(t, s.upsert(ctx, &Rule{
			Kind: "sa", Target: "12", Mode: "limited", Rate: &newRate, Burst: &burst,
		}))
		got, err := s.get(ctx, "sa", "12")
		require.NoError(t, err)
		require.Equal(t, int64(80), *got.Rate)
		require.Equal(t, int64(100), *got.Burst)
	})

	t.Run("upsert clears a field left nil", func(t *testing.T) {
		// The behaviour AdminPut relies on to implement an explicit null.
		other := int64(90)
		require.NoError(t, s.upsert(ctx, &Rule{
			Kind: "sa", Target: "12", Mode: "limited", Rate: &other,
		}))
		got, err := s.get(ctx, "sa", "12")
		require.NoError(t, err)
		require.Equal(t, int64(90), *got.Rate)
		require.Nil(t, got.Burst, "a nil field must reach the row as NULL")
	})

	t.Run("get returns nil when not found", func(t *testing.T) {
		got, err := s.get(ctx, "user", "999")
		require.NoError(t, err)
		require.Nil(t, got)
	})

	t.Run("list returns all rules", func(t *testing.T) {
		rate := int64(30)
		require.NoError(t, s.upsert(ctx, &Rule{
			Kind: "user", Target: "5", Mode: "limited", Rate: &rate,
		}))
		rules, err := s.list(ctx)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(rules), 2)
	})

	t.Run("delete removes rule", func(t *testing.T) {
		require.NoError(t, s.delete(ctx, "user", "5"))
		got, err := s.get(ctx, "user", "5")
		require.NoError(t, err)
		require.Nil(t, got)
	})

	t.Run("delete non-existent is no-op", func(t *testing.T) {
		require.NoError(t, s.delete(ctx, "nonexistent", "0"))
	})

}

// TestIntegrationDsRateLimitStore_UniqueIndex:
// the unique (kind, target) index is actually enforced. Without this
// assertion a silently-missing index would only be noticed in production
// (CreateTableSQL builds columns but not indexes, dialect.go:147-178).
func TestIntegrationDsRateLimitStore_UniqueIndex(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ss := db.InitTestDB(t)
	ctx := context.Background()

	rate := int64(30)
	err := ss.WithTransactionalDbSession(ctx, func(sess *sqlstore.DBSession) error {
		_, err := sess.Insert(&Rule{
			Kind: "user", Target: "1", Mode: "limited", Rate: &rate,
			Created: time.Now(), Updated: time.Now(),
		})
		return err
	})
	require.NoError(t, err)

	err = ss.WithTransactionalDbSession(ctx, func(sess *sqlstore.DBSession) error {
		_, err := sess.Insert(&Rule{
			Kind: "user", Target: "1", Mode: "blocked",
			Created: time.Now(), Updated: time.Now(),
		})
		return err
	})
	require.Error(t, err, "duplicate (user, 1) must be rejected by unique index")
}
