package migrations

import (
	. "github.com/grafana/grafana/pkg/services/sqlstore/migrator"
)

// addDsRateLimitMigration installs the schema for pkg/services/dsratelimit.
//
// There is no `lane` column. One was defined here originally, in anticipation of
// grouping rules into lanes, but nothing ever read or wrote it -- Rule has no
// such field, so every row was NULL from the first release. The global lane it
// belonged to has since been replaced by per-datasource quotas.
//
// It is removed from the CREATE TABLE rather than dropped by a follow-up
// migration because this table has not shipped: migrations are keyed by ID, so
// a drop would run forever on every future install to remove a column that
// never held data. Anyone who ran an earlier build of this branch keeps a
// harmless NULL column.
// See pkg/services/dsratelimit/model.go for column semantics; mode is an explicit
// enum ("limited" | "unlimited" | "blocked") instead of a magic rate value to
// avoid the x/time/rate Limit==0 trap (rate.go:345-356).
//
// This file lives in the migrations package (not in pkg/services/dsratelimit)
// because dsratelimit imports sqlstore, and sqlstore imports migrations — the
// v5 doc's proposed location would form an import cycle. Same layout as
// addQuotaMigration.
func addDsRateLimitMigration(mg *Migrator) {
	dsRateLimitV1 := Table{
		Name: "datasource_rate_limit",
		Columns: []*Column{
			{Name: "id", Type: DB_BigInt, IsPrimaryKey: true, IsAutoIncrement: true},
			{Name: "kind", Type: DB_NVarchar, Length: 16, Nullable: false}, // widened to 64 below; see the migration
			{Name: "target", Type: DB_NVarchar, Length: 64, Nullable: false},
			{Name: "mode", Type: DB_NVarchar, Length: 16, Nullable: false},
			{Name: "rate", Type: DB_BigInt, Nullable: true},
			{Name: "burst", Type: DB_BigInt, Nullable: true},
			{Name: "updated_by", Type: DB_BigInt, Nullable: true},
			{Name: "created", Type: DB_DateTime, Nullable: false},
			{Name: "updated", Type: DB_DateTime, Nullable: false},
		},
		Indices: []*Index{
			{Cols: []string{"kind", "target"}, Type: UniqueIndex},
		},
	}
	mg.AddMigration("create datasource_rate_limit table v1", NewAddTableMigration(dsRateLimitV1))
	addTableIndicesMigrations(mg, "v1", dsRateLimitV1)

	// concurrency is added as its own migration rather than as a column in the
	// CREATE TABLE above, because by the time it was needed the table had
	// shipped -- BOE was already running v1 with rows in it. Editing the
	// original would leave those installs without the column forever, since
	// migrations are keyed by ID and v1 has already been recorded as applied.
	//
	// Nullable with no default: NULL means "no per-identity override", the same
	// convention rate and burst already use. A row that sets only concurrency
	// leaves the QPS numbers alone, and vice versa, so the two layers stay
	// independently addressable through one table.
	mg.AddMigration("add concurrency to datasource_rate_limit",
		NewAddColumnMigration(dsRateLimitV1, &Column{
			Name: "concurrency", Type: DB_BigInt, Nullable: true,
		}))

	// kind was sized at 16 when the longest kind was "enforcement" (11). The
	// switch kinds added since do not fit: "concurrency_activation" is 22 and
	// "concurrency_enforcement" is 23, so writing either failed with a 500 on
	// MySQL -- the admin API accepted the rule, then the insert was refused by
	// the column.
	//
	// It went unnoticed because the tests run on SQLite, which does not enforce
	// VARCHAR length: every kind fits there regardless of the declared size, so
	// the failure only appears against a real MySQL. Caught by PUTting each
	// switch kind against a running server rather than by a test.
	//
	// 64 rather than 24, matching the target column: the cost is nothing and it
	// stops this from recurring the next time a kind is named descriptively.
	mg.AddMigration("widen datasource_rate_limit.kind to fit the switch kinds",
		NewRawSQLMigration("").
			Postgres("ALTER TABLE datasource_rate_limit ALTER COLUMN kind TYPE VARCHAR(64);").
			Mysql("ALTER TABLE datasource_rate_limit MODIFY kind NVARCHAR(64) NOT NULL;"))
}
