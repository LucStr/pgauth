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

var (
	rowKeys  = []string{"type", "locations", "identifier", "actions", "tables"}
	ruleKeys = []string{"name", "verbs"}
)

// ParseDetails reads the authorization_details claim and keeps the rows of type typ. Any key that is
// not an exact, single field (encoding/json would fold case and let duplicates win), any row of typ
// that is malformed or names another location than audience, fails.
func ParseDetails(raw json.RawMessage, typ, audience string) ([]Detail, error) {
	if err := checkKeys(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var rows []Detail
	if err := dec.Decode(&rows); err != nil {
		return nil, err
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

// DetailsClaim returns the raw authorization_details value of a JWT payload; any duplicate top-level
// key fails, so a second copy of the claim cannot win.
func DetailsClaim(payload []byte) (raw json.RawMessage, found bool, err error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	err = object(dec, nil, func(key string) error {
		if key != "authorization_details" {
			return skip(dec)
		}
		found = true
		return dec.Decode(&raw)
	})
	return raw, found, err
}

func checkKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	return array(dec, func() error {
		return object(dec, rowKeys, func(key string) error {
			if key != "tables" {
				return skip(dec)
			}
			return array(dec, func() error {
				return object(dec, ruleKeys, func(string) error { return skip(dec) })
			})
		})
	})
}

func delim(dec *json.Decoder, want json.Delim, what string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != want {
		return fmt.Errorf("must be %s", what)
	}
	return nil
}

func array(dec *json.Decoder, elem func() error) error {
	if err := delim(dec, '[', "an array"); err != nil {
		return err
	}
	for dec.More() {
		if err := elem(); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

// object walks one JSON object; allowed nil accepts any key, but every key may appear only once.
func object(dec *json.Decoder, allowed []string, value func(key string) error) error {
	if err := delim(dec, '{', "an object"); err != nil {
		return err
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key := tok.(string)
		switch {
		case allowed != nil && !slices.Contains(allowed, key):
			return fmt.Errorf("unknown field %q", key)
		case seen[key]:
			return fmt.Errorf("duplicate field %q", key)
		}
		seen[key] = true
		if err := value(key); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

func skip(dec *json.Decoder) error {
	var v json.RawMessage
	return dec.Decode(&v)
}
