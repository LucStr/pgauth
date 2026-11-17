// Package roles creates, reuses and removes temporary roles on one Postgres instance. Each process
// owns the roles it creates (ADR 0012): no other pgauth reuses them, and a sweep removes roles whose
// owner is gone or that outlived every connection that could use them.
package roles

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"crypto/pbkdf2"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Spec describes the temporary role one holder needs for one set of rights.
type Spec struct {
	Subject  string
	Username string
	ClientID string
	// Roles decide which holders may share a role: subject, client and these must all match.
	Roles  []string
	Groups []string
	// Expiry is the token's exp; the role's password stops working validFor after it.
	Expiry time.Time
}

func (s Spec) key() string {
	roles := slices.Clone(s.Roles)
	slices.Sort(roles)
	h := sha256.Sum256([]byte(s.Subject + "\x00" + s.ClientID + "\x00" + strings.Join(roles, ",")))
	return hex.EncodeToString(h[:])
}

func (s Spec) short() string {
	var b strings.Builder
	for _, r := range strings.ToLower(s.Subject) {
		if b.Len() == 8 {
			break
		}
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

type comment struct {
	Subject  string    `json:"sub"`
	Username string    `json:"user,omitempty"`
	ClientID string    `json:"client"`
	Created  time.Time `json:"created"`
	// Pod is the owning process's nonce; its advisory lock shows the owner is alive.
	Pod string `json:"pod"`
}

type Options struct {
	TempGroup string
	Prefix    string
	// ConnectionLimit is the role's CONNECTION LIMIT and how many pgauth connections share one role.
	ConnectionLimit int
	// MaxConnectionAge bounds a connection; a role is handed out for half of it, so every role is
	// unused after 1.5 × MaxConnectionAge.
	MaxConnectionAge time.Duration
	Log              *slog.Logger
	// Instance names the instance in the self-test metrics.
	Instance string
}

// validFor is how long after the token's exp a role's password still opens new logins.
const validFor = 5 * time.Minute

// sweepGrace is added to a role's longest possible life before the sweep treats it as leaked.
const sweepGrace = 10 * time.Minute

// lockClass namespaces pgauth's owner locks among advisory locks ("pgau").
const lockClass = 0x70676175

type Manager struct {
	pool  *pgxpool.Pool
	opts  Options
	nonce string

	ownerConn *pgxpool.Conn // holds the owner lock while this process lives

	mu      sync.Mutex
	current map[string]*entry // spec key → the role new connections get
	byName  map[string]*entry // every role this process created and has not removed

	dropFailed               metric.Int64Counter
	selfTestRuns             metric.Int64Counter
	selfTestOK, selfTestTime metric.Int64Gauge
	instance                 metric.MeasurementOption
}

type entry struct {
	mu         sync.Mutex
	name, key  string
	refs       int // guarded by Manager.mu
	created    time.Time
	validUntil time.Time
	password   string
	exists     bool
}

func NewManager(pool *pgxpool.Pool, opts Options) *Manager {
	if opts.ConnectionLimit <= 0 {
		opts.ConnectionLimit = 20
	}
	if opts.MaxConnectionAge <= 0 {
		opts.MaxConnectionAge = 12 * time.Hour
	}
	meter := otel.Meter("github.com/LucStr/pgauth")
	failed, _ := meter.Int64Counter("pgauth.roles.drop_failed",
		metric.WithDescription("Temporary roles that could not be dropped and were left NOLOGIN without rights"))
	runs, _ := meter.Int64Counter("pgauth.selftest.runs", metric.WithDescription("Temporary-role self-tests by result, pass or fail"))
	ok, _ := meter.Int64Gauge("pgauth.selftest.ok", metric.WithDescription("1 when the last temporary-role self-test passed, else 0"))
	at, _ := meter.Int64Gauge("pgauth.selftest.time", metric.WithDescription("When the last temporary-role self-test finished"), metric.WithUnit("s"))
	return &Manager{
		pool: pool, opts: opts, current: map[string]*entry{}, byName: map[string]*entry{}, dropFailed: failed,
		selfTestRuns: runs, selfTestOK: ok, selfTestTime: at, instance: metric.WithAttributes(attribute.String("pgauth.instance", opts.Instance)),
	}
}

// Start takes this process's owner lock under a fresh nonce; it must succeed before Acquire.
func (m *Manager) Start(ctx context.Context) error {
	for range 5 {
		nonce := randomName(6)
		conn, err := m.pool.Acquire(ctx)
		if err != nil {
			return err
		}
		var ok bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1, $2)", int32(lockClass), lockKey(nonce)).Scan(&ok); err != nil {
			conn.Release()
			return err
		}
		if ok {
			m.nonce, m.ownerConn = nonce, conn
			return nil
		}
		conn.Release()
	}
	return errors.New("could not take an owner lock")
}

// Stop releases the owner lock taken by Start; only before Run, which owns it after.
func (m *Manager) Stop() {
	m.ownerConn.Release()
}

// Nonce identifies this process in the names and comments of its roles.
func (m *Manager) Nonce() string { return m.nonce }

// OwnerLock is the advisory lock (class, key) a process holds while it owns roles under nonce.
func OwnerLock(nonce string) (int32, int32) { return int32(lockClass), lockKey(nonce) }

func lockKey(nonce string) int32 {
	h := sha256.Sum256([]byte(nonce))
	return int32(binary.BigEndian.Uint32(h[:4]))
}

// Acquire hands out a role for spec, creating one when there is none to reuse, and calls login with
// its name and password. Every successful Acquire must be paired with one Release.
func (m *Manager) Acquire(ctx context.Context, spec Spec, login func(role, password string) error) (role string, err error) {
	key := spec.key()
	m.mu.Lock()
	e := m.current[key]
	if e == nil || e.refs >= m.opts.ConnectionLimit || time.Since(e.created) > m.opts.MaxConnectionAge/2 {
		e = &entry{name: m.opts.Prefix + spec.short() + "_" + m.nonce + randomName(6), key: key, created: time.Now(), password: randomName(32)}
		m.current[key] = e
		m.byName[e.name] = e
	}
	e.refs++
	m.mu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	validUntil := spec.Expiry.Add(validFor)
	if spec.Expiry.IsZero() {
		validUntil = time.Now().Add(m.opts.MaxConnectionAge)
	}
	if !e.exists {
		err = m.create(ctx, e, spec, validUntil)
		e.exists = err == nil
	} else {
		err = m.refresh(ctx, e, validUntil)
	}
	if err == nil {
		err = login(e.name, e.password)
	}
	if err != nil {
		m.releaseLocked(ctx, e)
		return e.name, err
	}
	return e.name, nil
}

// Release removes role once the last connection using it has closed.
func (m *Manager) Release(ctx context.Context, role string) {
	m.mu.Lock()
	e := m.byName[role]
	m.mu.Unlock()
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	m.releaseLocked(ctx, e)
}

func (m *Manager) releaseLocked(ctx context.Context, e *entry) {
	m.mu.Lock()
	e.refs--
	last := e.refs == 0
	if last {
		delete(m.byName, e.name)
		if m.current[e.key] == e {
			delete(m.current, e.key)
		}
	}
	m.mu.Unlock()
	if last && e.exists {
		_ = m.remove(ctx, e.name)
		e.exists = false
	}
}

func (m *Manager) create(ctx context.Context, e *entry, spec Spec, validUntil time.Time) error {
	verifier, err := scramVerifier(e.password)
	if err != nil {
		return err
	}
	groups := append([]string{m.opts.TempGroup}, spec.Groups...)
	quoted := make([]string, len(groups))
	for i, g := range groups {
		quoted[i] = pgx.Identifier{g}.Sanitize()
	}
	c, err := json.Marshal(comment{Subject: spec.Subject, Username: spec.Username, ClientID: spec.ClientID, Created: e.created.UTC(), Pod: m.nonce})
	if err != nil {
		return err
	}
	ident := pgx.Identifier{e.name}.Sanitize()
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN INHERIT CONNECTION LIMIT %d PASSWORD %s VALID UNTIL %s IN ROLE %s",
		ident, m.opts.ConnectionLimit, literal(verifier), literal(validUntil.UTC().Format(time.RFC3339)), strings.Join(quoted, ", "))); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "COMMENT ON ROLE "+ident+" IS "+literal(string(c))); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	e.validUntil = validUntil
	return nil
}

// refresh resets the password before a reuse, so one the role set for itself stops working, and
// moves VALID UNTIL to the latest token's expiry.
func (m *Manager) refresh(ctx context.Context, e *entry, validUntil time.Time) error {
	verifier, err := scramVerifier(e.password)
	if err != nil {
		return err
	}
	validUntil = maxTime(validUntil, e.validUntil)
	if _, err := m.pool.Exec(ctx, "ALTER ROLE "+pgx.Identifier{e.name}.Sanitize()+" PASSWORD "+literal(verifier)+
		" VALID UNTIL "+literal(validUntil.UTC().Format(time.RFC3339))); err != nil {
		return err
	}
	e.validUntil = validUntil
	return nil
}

// remove takes a role's access away in an order it cannot undo: no new logins, no group rights,
// no sessions, then DROP ROLE. A role that still cannot be dropped stays NOLOGIN without rights,
// and is retried by the next sweep.
func (m *Manager) remove(ctx context.Context, role string) error {
	if err := m.removeRole(ctx, role); err != nil {
		return m.removeFailed(role, err)
	}
	return nil
}

func (m *Manager) removeRole(ctx context.Context, role string) error {
	conn, err := m.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	ident := pgx.Identifier{role}.Sanitize()
	if _, err := conn.Exec(ctx, "ALTER ROLE "+ident+" NOLOGIN"); err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return nil
		}
		return err
	}
	rows, err := conn.Query(ctx, `
		SELECT g.rolname FROM pg_auth_members am
		JOIN pg_roles g ON g.oid = am.roleid
		JOIN pg_roles r ON r.oid = am.member
		WHERE r.rolname = $1 AND g.rolname <> $2`, role, m.opts.TempGroup)
	if err != nil {
		return err
	}
	groups, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, g := range groups {
		if _, err := conn.Exec(ctx, "REVOKE "+pgx.Identifier{g}.Sanitize()+" FROM "+ident); err != nil {
			return err
		}
	}
	if _, err := conn.Exec(ctx, "SELECT pg_terminate_backend(pid, 2000) FROM pg_stat_activity WHERE usename = $1", role); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, "DROP ROLE IF EXISTS "+ident); err != nil {
		return err
	}
	return nil
}

func (m *Manager) removeFailed(role string, err error) error {
	m.dropFailed.Add(context.Background(), 1)
	m.opts.Log.Error("temporary role not dropped; left without login or rights where possible", "role", role, "error", err)
	return err
}

// StepError is the failed step of a self-test.
type StepError struct {
	Step string
	Err  error
}

func (e *StepError) Error() string { return e.Step + ": " + e.Err.Error() }
func (e *StepError) Unwrap() error { return e.Err }

// SelfTest creates a temporary role the way Acquire does, joined to groups, calls login with it and
// removes it. The role is never handed out; one left by a crash is swept once this process is gone.
func (m *Manager) SelfTest(ctx context.Context, groups []string, login func(role, password string) error) error {
	e := &entry{name: m.opts.Prefix + "_selftest_" + m.nonce + randomName(6), created: time.Now(), password: randomName(32)}
	m.mu.Lock()
	m.byName[e.name] = e
	m.mu.Unlock()
	spec := Spec{Subject: "pgauth self-test", ClientID: "pgauth", Groups: groups}
	err := m.create(ctx, e, spec, e.created.Add(validFor))
	if err != nil {
		err = &StepError{Step: "create temporary role", Err: err}
	} else if err = login(e.name, e.password); err != nil {
		err = &StepError{Step: "first login of temporary role", Err: err}
	}
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	derr := m.removeRole(dctx, e.name)
	cancel()
	if derr != nil && err == nil {
		err = &StepError{Step: "drop temporary role", Err: derr}
	}
	m.mu.Lock()
	delete(m.byName, e.name)
	m.mu.Unlock()
	ok, result := int64(0), "fail"
	if err == nil {
		ok, result = 1, "pass"
	}
	m.selfTestRuns.Add(ctx, 1, m.instance, metric.WithAttributes(attribute.String("result", result)))
	m.selfTestOK.Record(ctx, ok, m.instance)
	m.selfTestTime.Record(ctx, time.Now().Unix(), m.instance)
	return err
}

// Sweep removes temporary roles this process does not use, roles whose owning process is gone,
// and roles older than any connection could keep them.
func (m *Manager) Sweep(ctx context.Context) (removed int, err error) {
	rows, err := m.pool.Query(ctx, `
		SELECT r.rolname, coalesce(shobj_description(r.oid, 'pg_authid'), '')
		FROM pg_roles r
		JOIN pg_auth_members am ON am.member = r.oid
		JOIN pg_roles g ON g.oid = am.roleid
		WHERE g.rolname = $1 AND NOT am.admin_option AND r.rolname <> current_user AND starts_with(r.rolname, $2)`,
		m.opts.TempGroup, m.opts.Prefix)
	if err != nil {
		return 0, err
	}
	type candidate struct{ Role, Comment string }
	cands, err := pgx.CollectRows(rows, pgx.RowToStructByPos[candidate])
	if err != nil {
		return 0, err
	}
	maxLife := m.opts.MaxConnectionAge/2 + m.opts.MaxConnectionAge + sweepGrace
	for _, c := range cands {
		var meta comment
		_ = json.Unmarshal([]byte(c.Comment), &meta)
		switch {
		case meta.Pod == m.nonce:
			m.mu.Lock()
			_, inUse := m.byName[c.Role]
			m.mu.Unlock()
			if inUse && time.Since(meta.Created) < maxLife {
				continue
			}
		case meta.Pod != "" && time.Since(meta.Created) < maxLife:
			alive, err := m.ownerAlive(ctx, meta.Pod)
			if err != nil || alive {
				continue
			}
		}
		if m.remove(ctx, c.Role) == nil {
			removed++
		}
	}
	return removed, nil
}

func (m *Manager) ownerAlive(ctx context.Context, nonce string) (bool, error) {
	var alive bool
	err := m.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM pg_locks
		WHERE locktype = 'advisory' AND granted AND classid = $1 AND objid = $2 AND objsubid = 2
		AND database = (SELECT oid FROM pg_database WHERE datname = current_database()))`,
		uint32(lockClass), uint32(lockKey(nonce))).Scan(&alive)
	return alive, err
}

// Run sweeps every interval until ctx ends, taking the owner lock again if its connection broke.
func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := m.ownerConn.Ping(ctx); err != nil {
			m.ownerConn.Release()
			if err := m.relock(ctx); err != nil {
				m.opts.Log.Error("owner lock lost; skipping the sweep", "error", err)
				continue
			}
		}
		if n, err := m.Sweep(ctx); err != nil {
			m.opts.Log.Error("sweep temporary roles", "error", err)
		} else if n > 0 {
			m.opts.Log.Info("swept temporary roles", "removed", n)
		}
	}
}

func (m *Manager) relock(ctx context.Context) error {
	conn, err := m.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	var ok bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1, $2)", int32(lockClass), lockKey(m.nonce)).Scan(&ok); err != nil || !ok {
		conn.Release()
		return fmt.Errorf("owner lock taken: %v", err)
	}
	m.ownerConn = conn
	return nil
}

var lowerBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func randomName(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return lowerBase32.EncodeToString(b)[:n]
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// scramVerifier hashes password the way Postgres stores it, so the plain password never reaches the server's logs.
func scramVerifier(password string) (string, error) {
	const iterations = 4096
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", err
	}
	clientKey := hmacSum(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := hmacSum(salted, "Server Key")
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iterations, b64(salt), b64(storedKey[:]), b64(serverKey)), nil
}

func hmacSum(key []byte, msg string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}

func literal(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
