package rbac

import (
	"fmt"
	"strings"
	"testing"

	"github.com/LucStr/pgauth/internal/token"
)

func TestEffective(t *testing.T) {
	consent := func(id string, actions ...string) token.Detail {
		return token.Detail{Type: "postgres", Identifier: id, Actions: actions}
	}
	tables := func(id string, rules ...token.TableRule) token.Detail {
		return token.Detail{Type: "postgres", Identifier: id, Tables: rules}
	}
	rule := func(name string, verbs ...string) token.TableRule { return token.TableRule{Name: name, Verbs: verbs} }
	tests := []struct {
		name         string
		granted, cap Level
		details      []token.Detail
		want         string // "level" or "level tables", or "deny"
	}{
		{"no claim keeps bindings and cap", Write, Write, nil, "write"},
		{"no claim is capped by scope", Write, Read, nil, "read"},
		{"no claim without binding", None, Write, nil, "none"},
		{"empty claim denies", Write, Write, []token.Detail{}, "deny"},
		{"* read caps write", Write, Write, []token.Detail{consent("*", "read")}, "read"},
		{"exact write wins over * read", Write, Write, []token.Detail{consent("*", "read"), consent("main/order", "read", "write")}, "write"},
		{"exact read wins over * write", Write, Write, []token.Detail{consent("*", "write"), consent("main/order", "read")}, "read"},
		{"details never raise the bindings", Read, Write, []token.Detail{consent("main/order", "write")}, "read"},
		{"details never raise the scope cap", Write, Read, []token.Detail{consent("*", "write")}, "read"},
		{"other database only denies", Write, Write, []token.Detail{consent("main/assignment", "write")}, "deny"},
		{"other instance only denies", Write, Write, []token.Detail{consent("bidder/order", "write")}, "deny"},
		{"table rows reach only those tables", Write, Write, []token.Detail{
			consent("*", "read"), consent("main/order", "read", "write"),
			tables("main/order", rule("public.jobs", "update"), rule("public.customers", "select")),
		}, "write public.customers:select,public.jobs:update"},
		{"table rows without consent rows", Write, Write, []token.Detail{tables("main/order", rule("public.jobs", "delete", "select", "select"))}, "write public.jobs:delete,public.jobs:select"},
		{"select-only tables are read", Write, Write, []token.Detail{tables("main/order", rule("public.jobs", "select"))}, "read public.jobs:select"},
		{"verbs over the scope cap are dropped", Write, Read, []token.Detail{tables("main/order", rule("public.jobs", "update", "select"))}, "read public.jobs:select"},
		{"verbs over the bindings are dropped", Read, Write, []token.Detail{tables("main/order", rule("public.jobs", "update", "select"))}, "read public.jobs:select"},
		{"verbs over the consent row are dropped", Write, Write, []token.Detail{consent("main/order", "read"), tables("main/order", rule("public.jobs", "update", "select"))}, "read public.jobs:select"},
		{"nothing left denies", Read, Write, []token.Detail{tables("main/order", rule("public.jobs", "update"))}, "deny"},
		{"table rows of another database do not narrow this one", Write, Write, []token.Detail{consent("*", "write"), tables("main/assignment", rule("public.jobs", "select"))}, "write"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Effective(tt.granted, tt.cap, tt.details, "main", "order")
			s := got.Level.String()
			if got.Tables != nil {
				var ts []string
				for _, g := range got.Tables {
					ts = append(ts, g.String())
				}
				s = fmt.Sprintf("%s %s", s, strings.Join(ts, ","))
			}
			if err != nil {
				s = "deny"
			}
			if s != tt.want {
				t.Fatalf("Effective = %q (%v), want %q", s, err, tt.want)
			}
		})
	}
}
