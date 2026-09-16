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
			{Name: "kind", Type: DB_NVarchar, Length: 16, Nullable: false},
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
}
