package rbac

import (
	"fmt"
	"slices"
	"strings"

	"github.com/LucStr/pgauth/internal/token"
)

// Access is what one connection gets on a database: the whole database at Level when Tables is nil,
// otherwise only Tables, with Level the highest any of their verbs needs.
type Access struct {
	Level  Level
	Tables []TableGrant
}

// TableGrant is one verb (select, insert, update, delete) on one table.
type TableGrant struct{ Schema, Table, Verb string }

func (t TableGrant) String() string { return t.Schema + "." + t.Table + ":" + t.Verb }

func verbLevel(verb string) Level {
	if verb == "select" {
		return Read
	}
	return Write
}

// Effective narrows the bindings' level, capped by scope, by the token's authorization details. Nil
// details mean the token has no claim and change nothing. The consent level comes from rows naming
// instance/db, else from "*" rows; table rows for instance/db keep only verbs within it.
func Effective(granted, scopeCap Level, details []token.Detail, instance, db string) (Access, error) {
	level := min(granted, scopeCap)
	if details == nil || level == None {
		return Access{Level: level}, nil
	}
	id := instance + "/" + db
	exact, wildcard, hasExact, hasWildcard := None, None, false, false
	var tables []TableGrant
	for _, d := range details {
		if d.Identifier != id && d.Identifier != "*" {
			continue
		}
		for _, a := range d.Actions {
			lv := Read
			if a == "write" {
				lv = Write
			}
			if d.Identifier == id {
				exact, hasExact = max(exact, lv), true
			} else {
				wildcard, hasWildcard = max(wildcard, lv), true
			}
		}
		for _, t := range d.Tables {
			schema, table, _ := strings.Cut(t.Name, ".")
			for _, v := range t.Verbs {
				tables = append(tables, TableGrant{schema, table, v})
			}
		}
	}
	switch {
	case hasExact:
		level = min(level, exact)
	case hasWildcard:
		level = min(level, wildcard)
	case len(tables) == 0:
		return Access{}, fmt.Errorf("the token's authorization details grant nothing on %s", id)
	}
	if tables == nil {
		return Access{Level: level}, nil
	}
	slices.SortFunc(tables, func(a, b TableGrant) int { return strings.Compare(a.String(), b.String()) })
	tables = slices.Compact(tables)
	out := Access{Tables: []TableGrant{}}
	for _, t := range tables {
		if lv := verbLevel(t.Verb); lv <= level {
			out.Tables = append(out.Tables, t)
			out.Level = max(out.Level, lv)
		}
	}
	if len(out.Tables) == 0 {
		return Access{}, fmt.Errorf("the token's table rights on %s exceed its %s access", id, level)
	}
	return out, nil
}
