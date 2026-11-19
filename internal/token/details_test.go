package token

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseDetails(t *testing.T) {
	const aud = "https://postgres.example.test"
	row := func(extra string) string {
		return `{"type":"postgres","locations":["` + aud + `"],` + extra + `}`
	}
	tests := []struct {
		name    string
		claim   string
		want    string // identifiers of the kept rows, comma-separated
		wantErr string
	}{
		{"consent rows", `[` + row(`"identifier":"*","actions":["read"]`) + `,` + row(`"identifier":"main/order","actions":["read","write"]`) + `]`, "*,main/order", ""},
		{"table row", `[` + row(`"identifier":"main/order","tables":[{"name":"public.jobs","verbs":["update","select"]}]`) + `]`, "main/order", ""},
		{"other types are skipped", `[{"type":"clickhouse","locations":["https://ch"],"identifier":"events","tables":[{"name":"items","verbs":["select"]}]}]`, "", ""},
		{"empty array keeps an empty claim", `[]`, "", ""},
		{"unknown row field", `[` + row(`"identifier":"*","actions":["read"],"datatypes":["x"]`) + `]`, "", "unknown field"},
		{"unknown table field", `[` + row(`"identifier":"main/order","tables":[{"name":"public.jobs","verbs":["select"],"columns":["id"]}]`) + `]`, "", "unknown field"},
		{"unknown field on another type", `[{"type":"clickhouse","locations":["x"],"identifier":"*","actions":["read"],"x":1}]`, "", "unknown field"},
		{"wrong audience", `[{"type":"postgres","locations":["https://api.example.test"],"identifier":"*","actions":["read"]}]`, "", "locations"},
		{"two locations", `[{"type":"postgres","locations":["` + aud + `","` + aud + `"],"identifier":"*","actions":["read"]}]`, "", "locations"},
		{"identifier without instance", `[` + row(`"identifier":"order","actions":["read"]`) + `]`, "", "identifier"},
		{"identifier with two slashes", `[` + row(`"identifier":"a/b/c","actions":["read"]`) + `]`, "", "identifier"},
		{"unknown action", `[` + row(`"identifier":"*","actions":["admin"]`) + `]`, "", "unknown action"},
		{"actions and tables", `[` + row(`"identifier":"main/order","actions":["read"],"tables":[{"name":"public.jobs","verbs":["select"]}]`) + `]`, "", "not both"},
		{"neither actions nor tables", `[` + row(`"identifier":"main/order"`) + `]`, "", "needs actions or tables"},
		{"tables on *", `[` + row(`"identifier":"*","tables":[{"name":"public.jobs","verbs":["select"]}]`) + `]`, "", "<instance>/<db>"},
		{"table without schema", `[` + row(`"identifier":"main/order","tables":[{"name":"jobs","verbs":["select"]}]`) + `]`, "", "<schema>.<table>"},
		{"table without verbs", `[` + row(`"identifier":"main/order","tables":[{"name":"public.jobs","verbs":[]}]`) + `]`, "", "no verbs"},
		{"unknown verb", `[` + row(`"identifier":"main/order","tables":[{"name":"public.jobs","verbs":["truncate"]}]`) + `]`, "", "unknown verb"},
		{"not an array", row(`"identifier":"*","actions":["read"]`), "", "must be an array"},
		{"null", `null`, "", "must be an array"},
		{"long-s key folding onto actions", `[` + row(`"identifier":"*","actions":["read"],"actionſ":["write"]`) + `]`, "", "unknown field"},
		{"capitalised key", `[` + row(`"identifier":"*","Actions":["write"]`) + `]`, "", "unknown field"},
		{"duplicate key", `[` + row(`"identifier":"*","actions":["read"],"actions":["write"]`) + `]`, "", "duplicate field"},
		{"duplicate key in a table rule", `[` + row(`"identifier":"main/order","tables":[{"name":"public.jobs","verbs":["select"],"verbs":["delete"]}]`) + `]`, "", "duplicate field"},
		{"claim in a payload", `{"sub":"x","authorization_details":[` + row(`"identifier":"*","actions":["read"]`) + `]}`, "*", ""},
		{"claim twice in a payload", `{"authorization_details":[],"authorization_details":[` + row(`"identifier":"*","actions":["write"]`) + `]}`, "", "duplicate field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.RawMessage(tt.claim), error(nil)
			if strings.Contains(tt.claim, `"authorization_details"`) {
				raw, _, err = DetailsClaim([]byte(tt.claim))
			}
			var got []Detail
			if err == nil {
				got, err = ParseDetails(raw, "postgres", aud)
			}
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got == nil {
				t.Fatalf("got %v, %v", got, err)
			}
			var ids []string
			for _, d := range got {
				ids = append(ids, d.Identifier)
			}
			if strings.Join(ids, ",") != tt.want {
				t.Fatalf("rows = %v, want %s", ids, tt.want)
			}
		})
	}
}
