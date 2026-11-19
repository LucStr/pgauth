package token

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Detail is one authorization_details row (RFC 9396): a consent row carries Actions, a run row Tables.
type Detail struct {
	Type       string      `json:"type"`
	Locations  []string    `json:"locations"`
	Identifier string      `json:"identifier"`
	Actions    []string    `json:"actions,omitempty"`
	Tables     []TableRule `json:"tables,omitempty"`
}

// TableRule names one "<schema>.<table>" and the verbs a run may use on it.
type TableRule struct {
	Name  string   `json:"name"`
	Verbs []string `json:"verbs"`
}

var (
	actions = []string{"read", "write"}
	verbs   = []string{"select", "insert", "update", "delete"}
)

// ParseDetails reads the authorization_details claim and keeps the rows of type typ. Any field it
// does not know, or a row of typ that is malformed or names another location than audience, fails.
func ParseDetails(raw any, typ, audience string) ([]Detail, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var rows []Detail
	if err := dec.Decode(&rows); err != nil {
		return nil, fmt.Errorf("not an array of details: %w", err)
	}
	if rows == nil {
		return nil, errors.New("must be an array")
	}
	out := []Detail{}
	for i, d := range rows {
		if d.Type != typ {
			continue
		}
		if err := d.check(audience); err != nil {
			return nil, fmt.Errorf("row %d: %w", i, err)
		}
		out = append(out, d)
	}
	return out, nil
}

func (d Detail) check(audience string) error {
	if len(d.Locations) != 1 || d.Locations[0] != audience {
		return fmt.Errorf("locations must be exactly [%q]", audience)
	}
	if d.Identifier != "*" {
		inst, db, ok := strings.Cut(d.Identifier, "/")
		if !ok || inst == "" || db == "" || strings.Contains(db, "/") {
			return fmt.Errorf("identifier %q is neither * nor <instance>/<db>", d.Identifier)
		}
	}
	switch {
	case len(d.Actions) > 0 && len(d.Tables) > 0:
		return errors.New("a row has actions or tables, not both")
	case len(d.Actions) > 0:
		for _, a := range d.Actions {
			if !slices.Contains(actions, a) {
				return fmt.Errorf("unknown action %q", a)
			}
		}
	case len(d.Tables) > 0:
		if d.Identifier == "*" {
			return errors.New("table rows need an <instance>/<db> identifier")
		}
		for _, t := range d.Tables {
			schema, table, ok := strings.Cut(t.Name, ".")
			if !ok || schema == "" || table == "" {
				return fmt.Errorf("table %q is not <schema>.<table>", t.Name)
			}
			if len(t.Verbs) == 0 {
				return fmt.Errorf("table %s has no verbs", t.Name)
			}
			for _, v := range t.Verbs {
				if !slices.Contains(verbs, v) {
					return fmt.Errorf("table %s: unknown verb %q", t.Name, v)
				}
			}
		}
	default:
		return errors.New("a row needs actions or tables")
	}
	return nil
}
