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

// tableGroupName is the group role holding one verb on one relation; keyed by OID because grants
// follow the relation, so a renamed table never lends its group to a new one under the old name.
func (m *Manager) tableGroupName(db string, oid uint32, verb string) string {
	h := sha256.Sum256(fmt.Appendf(nil, "%s\x00%d\x00%s", db, oid, verb))
	return m.opts.Prefix + "t_" + hex.EncodeToString(h[:8])
}

// privileges is what a role holds for one verb on one table: USAGE on the schema, the verb on the
// table, USAGE on its owned sequences (insert only) and CONNECT on the database.
type privileges struct {
	exists, schema, table, sequences, connect bool
	seqs                                      []string
}

func (p privileges) all() bool { return p.exists && p.schema && p.table && p.sequences && p.connect }

const privilegesQuery = `
	WITH g AS (SELECT oid FROM pg_roles WHERE rolname = $1),
	seqs AS (
		SELECT s.oid FROM pg_depend d JOIN pg_class s ON s.oid = d.objid AND s.relkind = 'S'
		WHERE d.classid = 'pg_class'::regclass AND d.refobjid = $3::text::regclass AND d.deptype IN ('a', 'i'))
	SELECT EXISTS (SELECT 1 FROM g),
		coalesce((SELECT has_schema_privilege(g.oid, $2::text, 'USAGE') FROM g), false),
		coalesce((SELECT has_table_privilege(g.oid, $3::text, $4::text) FROM g), false),
		$4::text <> 'INSERT' OR coalesce((SELECT NOT EXISTS (SELECT 1 FROM seqs WHERE NOT has_sequence_privilege(g.oid, seqs.oid, 'USAGE')) FROM g), false),
		coalesce((SELECT has_database_privilege(g.oid, current_database(), 'CONNECT') FROM g), false),
		ARRAY(SELECT oid::regclass::text FROM seqs ORDER BY 1)`

func readPrivileges(ctx context.Context, conn *pgx.Conn, role string, t rbac.TableGrant) (privileges, error) {
	var p privileges
	table := pgx.Identifier{t.Schema, t.Table}.Sanitize()
	err := conn.QueryRow(ctx, privilegesQuery, role, t.Schema, table, strings.ToUpper(t.Verb)).
		Scan(&p.exists, &p.schema, &p.table, &p.sequences, &p.connect, &p.seqs)
	return p, err
}

// TableGroup returns the table group for t. bindingGroup is the group role the holder's binding would
// join (read for select, write otherwise); t is refused unless that group already holds it, so table
// intent never reaches a table the binding cannot. Missing grants are added; conn is the issuer on db.
func (m *Manager) TableGroup(ctx context.Context, conn *pgx.Conn, db, bindingGroup string, t rbac.TableGrant) (string, error) {
	var oid uint32
	var kind string
	var rls bool
	if err := conn.QueryRow(ctx, "SELECT oid, relkind::text, relrowsecurity FROM pg_class WHERE oid = $1::text::regclass",
		pgx.Identifier{t.Schema, t.Table}.Sanitize()).Scan(&oid, &kind, &rls); err != nil {
		return "", err
	}
	if kind != "r" && kind != "p" {
		return "", fmt.Errorf("%s.%s is not a table", t.Schema, t.Table)
	}
	if rls {
		return "", fmt.Errorf("%s.%s has row-level security, whose policies name the database groups, not table groups", t.Schema, t.Table)
	}
	name := m.tableGroupName(db, oid, t.Verb)
	verb := strings.ToUpper(t.Verb)
	bound, err := readPrivileges(ctx, conn, bindingGroup, t)
	if err != nil {
		return name, err
	}
	if !bound.all() {
		return name, fmt.Errorf("%s on %s.%s is outside what %s grants", verb, t.Schema, t.Table, bindingGroup)
	}
	have, err := readPrivileges(ctx, conn, name, t)
	if err != nil || have.all() {
		return name, err
	}
	m.tableMu.Lock()
	defer m.tableMu.Unlock()
	group := pgx.Identifier{name}.Sanitize()
	if !have.exists {
		_, err := conn.Exec(ctx, "CREATE ROLE "+group+" NOLOGIN")
		var pgErr *pgconn.PgError
		if err != nil && !(errors.As(err, &pgErr) && (pgErr.Code == "42710" || pgErr.Code == "23505")) {
			return name, err
		}
	}
	var stmts []string
	if !have.schema {
		stmts = append(stmts, "GRANT USAGE ON SCHEMA "+pgx.Identifier{t.Schema}.Sanitize()+" TO "+group)
	}
	if !have.table {
		stmts = append(stmts, "GRANT "+verb+" ON "+pgx.Identifier{t.Schema, t.Table}.Sanitize()+" TO "+group)
	}
	if !have.sequences && len(have.seqs) > 0 {
		stmts = append(stmts, "GRANT USAGE ON SEQUENCE "+strings.Join(have.seqs, ", ")+" TO "+group)
	}
	if !have.connect {
		stmts = append(stmts, "GRANT CONNECT ON DATABASE "+pgx.Identifier{db}.Sanitize()+" TO "+group)
	}
	for _, stmt := range stmts {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return name, err
		}
	}
	if have, err = readPrivileges(ctx, conn, name, t); err != nil {
		return name, err
	}
	if !have.all() {
		return name, fmt.Errorf("the issuer cannot grant %s on %s.%s: it needs the privileges WITH GRANT OPTION", verb, t.Schema, t.Table)
	}
	return name, nil
}
