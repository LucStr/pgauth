package roles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/LucStr/pgauth/internal/rbac"
)

// TableGroupName is the group role holding one verb on one table; groups are shared and never dropped.
func (m *Manager) TableGroupName(db string, t rbac.TableGrant) string {
	h := sha256.Sum256([]byte(db + "\x00" + t.Schema + "\x00" + t.Table + "\x00" + t.Verb))
	return m.opts.Prefix + "t_" + hex.EncodeToString(h[:8])
}

// tableGroupState reports whether group exists and already holds verb on table, USAGE on schema and,
// for insert, USAGE on the table's owned sequences; seqs are those sequences.
const tableGroupState = `
	WITH g AS (SELECT oid FROM pg_roles WHERE rolname = $1),
	seqs AS (
		SELECT s.oid FROM pg_depend d JOIN pg_class s ON s.oid = d.objid AND s.relkind = 'S'
		WHERE d.classid = 'pg_class'::regclass AND d.refobjid = $3::text::regclass AND d.deptype IN ('a', 'i'))
	SELECT EXISTS (SELECT 1 FROM g),
		coalesce((SELECT has_schema_privilege(g.oid, $2::text, 'USAGE') AND has_table_privilege(g.oid, $3::text, $4::text)
			AND ($4::text <> 'INSERT' OR NOT EXISTS (SELECT 1 FROM seqs WHERE NOT has_sequence_privilege(g.oid, seqs.oid, 'USAGE')))
			FROM g), false),
		ARRAY(SELECT oid::regclass::text FROM seqs ORDER BY 1)`

// TableGroup returns the table group for t, creating it and granting the verb, USAGE on the schema and,
// for insert, USAGE on owned sequences only when missing. conn is the issuer connected to db.
func (m *Manager) TableGroup(ctx context.Context, conn *pgx.Conn, db string, t rbac.TableGrant) (string, error) {
	name := m.TableGroupName(db, t)
	schema, table := pgx.Identifier{t.Schema}.Sanitize(), pgx.Identifier{t.Schema, t.Table}.Sanitize()
	verb := strings.ToUpper(t.Verb)
	var exists, ok bool
	var seqs []string
	state := func() error {
		return conn.QueryRow(ctx, tableGroupState, name, t.Schema, table, verb).Scan(&exists, &ok, &seqs)
	}
	if err := state(); err != nil || ok {
		return name, err
	}
	m.tableMu.Lock()
	defer m.tableMu.Unlock()
	group := pgx.Identifier{name}.Sanitize()
	if !exists {
		_, err := conn.Exec(ctx, "CREATE ROLE "+group+" NOLOGIN")
		var pgErr *pgconn.PgError
		if err != nil && !(errors.As(err, &pgErr) && (pgErr.Code == "42710" || pgErr.Code == "23505")) {
			return name, err
		}
	}
	stmts := []string{"GRANT USAGE ON SCHEMA " + schema + " TO " + group, "GRANT " + verb + " ON " + table + " TO " + group}
	if verb == "INSERT" && len(seqs) > 0 {
		stmts = append(stmts, "GRANT USAGE ON SEQUENCE "+strings.Join(seqs, ", ")+" TO "+group)
	}
	for _, stmt := range stmts {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return name, err
		}
	}
	if err := state(); err != nil {
		return name, err
	}
	if !ok {
		return name, fmt.Errorf("the issuer cannot grant %s on %s.%s: it needs the privilege WITH GRANT OPTION", verb, t.Schema, t.Table)
	}
	return name, nil
}
