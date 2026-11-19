// Package api serves pgauth's HTTPS endpoints: public discovery for connectors, and the access a
// token has, so a client can list what it may reach without trying every database.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/LucStr/pgauth/internal/config"
	"github.com/LucStr/pgauth/internal/rbac"
	"github.com/LucStr/pgauth/internal/token"
)

// Discovery is the body of GET /.well-known/pgauth.
type Discovery struct {
	Postgres    string     `json:"postgres"`
	Issuer      string     `json:"issuer"`
	Audience    string     `json:"audience"`
	CLIClientID string     `json:"cli_client_id"`
	Scopes      Scopes     `json:"scopes"`
	Instances   []Instance `json:"instances"`
	// AccessHelp says where to ask for access; empty when the server sets none.
	AccessHelp string `json:"access_help,omitempty"`
}

type Scopes struct {
	Read  string `json:"read"`
	Write string `json:"write"`
}

type Instance struct {
	Name      string   `json:"name"`
	Databases []string `json:"databases"`
}

// Access is one entry of GET /v1/access: a database the token reaches and its level after the scope cap.
type Access struct {
	Instance string `json:"instance"`
	Database string `json:"database"`
	Level    string `json:"level"`
}

// Table is one entry of GET /v1/tables; EstimatedRows comes from the planner statistics.
type Table struct {
	Schema        string `json:"schema"`
	Table         string `json:"table"`
	EstimatedRows int64  `json:"estimatedRows"`
}

// TableLister lists the tables of instance/db with their estimated row counts.
type TableLister func(ctx context.Context, instance, db string) ([]Table, error)

type Server struct {
	cfg      *config.Config
	verifier *token.Verifier
	rbac     *rbac.Store
	tables   TableLister
}

func New(cfg *config.Config, verifier *token.Verifier, store *rbac.Store, tables TableLister) *Server {
	return &Server{cfg: cfg, verifier: verifier, rbac: store, tables: tables}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/pgauth", s.discovery)
	mux.HandleFunc("GET /v1/access", s.access)
	mux.HandleFunc("GET /v1/tables", s.listTables)
	return mux
}

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	d := Discovery{
		Postgres:    s.cfg.Discovery.Postgres,
		Issuer:      s.cfg.OIDC.Issuer,
		Audience:    s.cfg.OIDC.Audience,
		CLIClientID: s.cfg.Discovery.CLIClientID,
		Scopes:      Scopes{Read: s.cfg.OIDC.Scopes.Read, Write: s.cfg.OIDC.Scopes.Write},
		AccessHelp:  s.cfg.AccessHelp,
	}
	if d.Postgres == "" {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		_, port, _ := net.SplitHostPort(s.cfg.Listen)
		d.Postgres = net.JoinHostPort(host, port)
	}
	for _, in := range s.cfg.Instances {
		d.Instances = append(d.Instances, Instance{Name: in.Name, Databases: in.Databases})
	}
	writeJSON(w, http.StatusOK, d)
}

// holder verifies the bearer token and returns a function giving its access on one database, or
// writes the error and returns nil.
func (s *Server) holder(w http.ResponseWriter, r *http.Request) func(instance, db string) (rbac.Access, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		writeError(w, http.StatusUnauthorized, "send the database token as Authorization: Bearer <token>")
		return nil
	}
	claims, err := s.verifier.Verify(r.Context(), raw)
	if err != nil {
		code := http.StatusUnauthorized
		if !errors.Is(err, token.ErrDenied) {
			code = http.StatusInternalServerError
		}
		writeError(w, code, err.Error())
		return nil
	}
	policy := s.rbac.Policy()
	if policy == nil {
		writeError(w, http.StatusServiceUnavailable, "access rules are not loaded")
		return nil
	}
	scopeCap := rbac.ScopeCap(claims.Scopes, s.cfg.OIDC.Scopes.Read, s.cfg.OIDC.Scopes.Write)
	who := rbac.Who{User: claims.Username, Groups: claims.Groups, FoldUser: s.cfg.OIDC.FoldUsername()}
	return func(instance, db string) (rbac.Access, error) {
		granted, _ := policy.Access(who, instance, db)
		return rbac.Effective(granted, scopeCap, claims.Details, instance, db)
	}
}

func (s *Server) access(w http.ResponseWriter, r *http.Request) {
	access := s.holder(w, r)
	if access == nil {
		return
	}
	out := []Access{}
	for _, in := range s.cfg.Instances {
		for _, db := range in.Databases {
			if a, err := access(in.Name, db); err == nil && a.Level > rbac.None {
				out = append(out, Access{Instance: in.Name, Database: db, Level: a.Level.String()})
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listTables(w http.ResponseWriter, r *http.Request) {
	access := s.holder(w, r)
	if access == nil {
		return
	}
	id := r.URL.Query().Get("db")
	instance, db, _ := strings.Cut(id, "/")
	served := false
	for _, in := range s.cfg.Instances {
		served = served || in.Name == instance && in.Serves(db)
	}
	if !served {
		writeError(w, http.StatusNotFound, fmt.Sprintf("database %q is not served; db must be <instance>/<db>", id))
		return
	}
	a, err := access(instance, db)
	if err == nil && a.Level == rbac.None {
		err = fmt.Errorf("no access to %s", id)
	}
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	tables, err := s.tables(r.Context(), instance, db)
	if err != nil {
		writeError(w, http.StatusBadGateway, "list tables: "+err.Error())
		return
	}
	if a.Tables != nil {
		tables = slices.DeleteFunc(tables, func(t Table) bool {
			return !slices.ContainsFunc(a.Tables, func(g rbac.TableGrant) bool { return g.Schema == t.Schema && g.Table == t.Table })
		})
	}
	writeJSON(w, http.StatusOK, tables)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
