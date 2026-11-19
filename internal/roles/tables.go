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
	return m.opts.Prefix + "t_" + hex.EncodeToString(h[:4])
}

// TableGroup creates the table group for t if it is missing and grants it the verb and USAGE on the
// schema. conn is the issuer connected to db. A grant the issuer cannot give (no GRANT OPTION) fails.
func (m *Manager) TableGroup(ctx context.Context, conn *pgx.Conn, db string, t rbac.TableGrant) (string, error) {
	m.tableMu.Lock()
	defer m.tableMu.Unlock()
	name := m.TableGroupName(db, t)
	group := pgx.Identifier{name}.Sanitize()
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", name).Scan(&exists); err != nil {
		return name, err
	}
	if !exists {
		_, err := conn.Exec(ctx, "CREATE ROLE "+group+" NOLOGIN")
		var pgErr *pgconn.PgError
		if err != nil && !(errors.As(err, &pgErr) && (pgErr.Code == "42710" || pgErr.Code == "23505")) {
			return name, err
		}
	}
	schema, table := pgx.Identifier{t.Schema}.Sanitize(), pgx.Identifier{t.Schema, t.Table}.Sanitize()
	verb := strings.ToUpper(t.Verb)
	for _, stmt := range []string{"GRANT USAGE ON SCHEMA " + schema + " TO " + group, "GRANT " + verb + " ON " + table + " TO " + group} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return name, err
		}
	}
	var ok bool
	if err := conn.QueryRow(ctx, "SELECT has_schema_privilege($1, $2, 'USAGE') AND has_table_privilege($1, $3, $4)",
		name, t.Schema, table, verb).Scan(&ok); err != nil {
		return name, err
	}
	if !ok {
		return name, fmt.Errorf("the issuer cannot grant %s on %s.%s: it needs the privilege WITH GRANT OPTION", verb, t.Schema, t.Table)
	}
	return name, nil
}
