# pgauth

pgauth lets people and programs log in to Postgres with a short-lived OIDC access token instead of a
database password. A client connects to pgauth with the token as its password; pgauth verifies the
token, looks up what the holder may do in Kubernetes-style role bindings, creates a temporary Postgres
role with exactly that access, logs in upstream as that role and passes bytes through. When the last connection using the role closes,
pgauth drops it.

```
psql "host=pgauth.example.com dbname=main/orders sslmode=verify-full" # password: an access token
```

## What pgauth is not

- **Not a fine-grained authorization engine.** pgauth decides read, write or nothing on a database,
  from role bindings (see [Access model](#access-model)); a token's authorization details can only
  narrow that, down to verbs on named tables. Row and column rules stay in Postgres grants. Projects like [pgauthz](https://github.com/thomasdarimont/pgauthz) evaluate
  authorization inside Postgres; pgauth does not.
- **Not a connection pooler.** Every client connection is one upstream connection. PgBouncer or
  another pooler can sit behind pgauth if you need pooling.
- **Not a query firewall.** pgauth never reads query text. Rights come only from the Postgres group
  roles the temporary role joins.

## How it works

1. The client sends `SSLRequest`; pgauth requires TLS before anything else.
2. The startup message's database is `<instance>/<db>`. pgauth asks for a cleartext password, which
   is the access token.
3. pgauth verifies the token against the issuer's JWKS: signature, `iss`, `aud`, `exp`, and the client
   allowlist.
4. The token names a user (`email` by default) and groups (`groups`). The role bindings decide the
   level on the requested database, the token's scope caps it (see [Access model](#access-model)),
   the token's authorization details may narrow it further, and the level picks the group roles: read
   joins `<db>_read`, write joins `<db>_read` and `<db>_write` (`groupRoles`); table intent joins only
   the table groups instead. No access means no connection.
5. pgauth creates or reuses the temporary role `pgauth_<sub8>_<hash6>`, where `hash6` covers the
   subject, client, database, level and group roles. The role is a member of those group roles, of
   `pgauth_temp` and, when the instance sets `statsRole`, of that role, carries `COMMENT ON ROLE` with the full subject, user, client and creation time, and
   has a password only pgauth knows, `CONNECTION LIMIT roleConnectionLimit` (20) and `VALID UNTIL` the
   token's expiry plus 5 minutes, which only caps new logins
   ([ADR 0003](docs/adr/0003-drop-roles-not-valid-until.md), [0012](docs/adr/0012-each-process-owns-its-roles.md)).
6. pgauth logs in upstream as the role and splices the two connections. Access is checked only here,
   at connect ([ADR 0004](docs/adr/0004-check-at-the-gate-only.md)); `maxConnectionAge` (default 12h)
   bounds how long a connection lives.
7. When the last connection using a role closes, pgauth removes it in an order the role cannot undo:
   `NOLOGIN`, revoke its groups, terminate every session of it (including any it opened directly with
   a password it set itself), `DROP ROLE`. A role that cannot be dropped (it created a large object or
   default privileges) stays without login or rights, is logged and counted in
   `pgauth.roles.drop_failed`, and is retried by the sweep.

Cancel requests work: pgauth hands the client its own cancel key and forwards cancels upstream.

## Access model

pgauth reads `PgRole` and `PgRoleBinding` resources from every `*.yaml` file in `rbac.dir` (several
documents per file are fine; `kustomization.yaml` is skipped). They work like Kubernetes RBAC:

```yaml
apiVersion: pgauth.dev/v1alpha1
kind: PgRole
metadata: {name: analytics-reader}
spec:
  grants:
    - {instance: cloudsql-main, database: order, level: read}  # level: read|write; database "*" = every database of the instance
---
apiVersion: pgauth.dev/v1alpha1
kind: PgRoleBinding
metadata: {name: mari-order}
spec:
  roleRef: {kind: PgRole, name: cloudsql-main.order.read}
  subjects:
    - {kind: Group, name: postgres-admins}
    - {kind: User, name: mari@example.com}
```

- **Subjects.** `User` matches the token's `oidc.usernameClaim` (default `email`), ignoring case
  (Unicode simple case folding) unless `oidc.usernameCaseInsensitive: false`, because issuers often
  keep the stored casing of an email. `Group` matches each entry of `oidc.groupsClaim` (default
  `groups`) exactly, after `oidc.groupsPrefix` is prepended; the claim may be an array or, for a single
  group, a plain string.
- **Built-in roles** need no YAML: `pg-admin` (write on every configured database), `pg-reader`
  (read on every configured database), and `<instance>.<db>.read` / `<instance>.<db>.write` for
  every database in `instances`. A `PgRole` may not reuse their names.
- **Effective access** is the highest level over every binding that matches the user or one of their
  groups. Write implies read.
- **Scope cap.** After the bindings, the token's scope caps the level: `postgres:read` caps at read,
  `postgres:write` allows write, a token with neither is refused (`oidc.scopes` renames them). This is
  how a token issued to an agent stays read-only although its owner may write.
- **Authorization details** ([RFC 9396](https://www.rfc-editor.org/rfc/rfc9396), [ADR 0013](docs/adr/0013-authorization-details-narrow-to-tables.md)).
  A token with an `authorization_details` claim is narrowed by its rows of type `oidc.detailsType`
  (default `postgres`); a token without the claim is unaffected, unless its client is listed in
  `oidc.requireDetailsClients`: such a token without the claim is refused, so an agent client can
  never fall back to its owner's full bindings (Rapidata lists `poseidon-session` and `poseidon-run`;
  `pgauth-cli` stays claim-free). A connection with table intent lives at most until the token's
  `exp`, not `maxConnectionAge`.

  ```json
  [{"type":"postgres","locations":["<audience>"],"identifier":"*","actions":["read"]},
   {"type":"postgres","locations":["<audience>"],"identifier":"cloudsql-main/order","actions":["read","write"]},
   {"type":"postgres","locations":["<audience>"],"identifier":"cloudsql-main/order",
    "tables":[{"name":"public.jobs","verbs":["update","select"]}]}]
  ```

  `locations` must be exactly the audience; `identifier` is `*` or `<instance>/<db>`, and rows for the
  database win over `*`. `actions` (read, write) cap the level; `tables` (`<schema>.<table>`, verbs
  select, insert, update, delete) limit that database to those tables. Verbs above the bindings, scope
  or consent level of that database (its own row, else `*`) are dropped, and a database left with
  nothing is refused, as is a token whose claim has an unknown field or a malformed row. The verb is
  granted literally: `UPDATE … WHERE` also needs `select`; `insert` also gets `USAGE` on the table's
  owned sequences (serial and identity columns). A table verb is refused unless the group the binding
  would join already holds it (`<db>_read` for select, `<db>_write` otherwise, with `USAGE` on the
  schema and, for insert, the sequences), so table intent never reaches a table the binding cannot; a view or any other relation that is not
  a table is refused, and so is a table with row-level security (its policies name `<db>_read` /
  `<db>_write`, not table groups). An issuer declaring `update` or `delete` should pair it with
  `select` on the same table.
  Each verb on a table is a group role `pgauth_t_<hash16>` keyed by the table's OID (NOLOGIN, the verb,
  `USAGE` on the schema, `CONNECT` on the database) that pgauth creates and grants on first use and
  never drops; later connections only read the catalog, and a renamed or recreated table gets a new
  group. A connection with table intent does not join `statsRole`.
- **Reloading.** pgauth rereads the directory every `rbac.reloadInterval` (10s) and loads a change
  only after two identical reads 100 ms apart, so a file being written is picked up once it is
  complete. A set with any error is rejected as a whole and the last valid set stays live; a file with
  no `PgRole` or `PgRoleBinding` (for example one caught empty mid-write) counts as an error, so
  delete a file rather than emptying it; the rejection is logged, counted in the
  `pgauth.rbac.loads{result="rejected"}` metric, flagged by the `pgauth.rbac.rejected` gauge and shown
  in the `/readyz` body. pgauth becomes ready only once a first valid set has loaded.
- **Lint in CI.** `pgauth lint [--config config.yaml] <dir>` checks the schema, unknown fields,
  duplicate names, role references, subject kinds and, with `--config`, every instance, database and
  generated role against the config, and, when `oidc.usernameCaseInsensitive` is false, warns (exit 0) about `User` names with uppercase
  letters. It reads only those files (not the TLS or credentials files they
  name), makes no network calls, prints `file:line: message` and exits 1 on any error.

Files first, CRDs later with the same format, and lint plus last-valid-wins instead of an admission
webhook: [ADR 0008](docs/adr/0008-role-bindings-files-first.md).

Every connection attempt records the matched bindings, the level they grant, the level after the cap
and the cap itself
(see [Running](#running)).

## Preparing an instance

Run once per instance as a superuser (Cloud SQL: a `cloudsqlsuperuser` member), and once per database:

```sql
-- per instance
CREATE ROLE pgauth_temp NOLOGIN;
CREATE ROLE pgauth LOGIN PASSWORD '...' CREATEROLE;
GRANT pg_signal_backend TO pgauth;
GRANT pgauth_temp TO pgauth WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;

-- per database <db>, whose tables are owned by <db>_service
CREATE ROLE <db>_read NOLOGIN;
CREATE ROLE <db>_write NOLOGIN;
GRANT <db>_read, <db>_write TO pgauth WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;

-- per database <db>, connected to <db>
GRANT USAGE ON SCHEMA public TO <db>_read, <db>_write;
ALTER DEFAULT PRIVILEGES FOR ROLE <db>_service IN SCHEMA public
  GRANT SELECT ON TABLES TO <db>_read;
ALTER DEFAULT PRIVILEGES FOR ROLE <db>_service IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO <db>_write;
-- tables that already exist need the same grants once:
GRANT SELECT ON ALL TABLES IN SCHEMA public TO <db>_read;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO <db>_write;
-- so writers (and table intent with insert) can use serial and identity sequences:
ALTER DEFAULT PRIVILEGES FOR ROLE <db>_service IN SCHEMA public
  GRANT USAGE ON SEQUENCES TO <db>_write;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO <db>_write;
```

For table intent ([authorization details](#access-model)) the issuer must also be able to grant
table privileges; give them to the issuer directly, never `WITH GRANT OPTION` to `<db>_write`, which
every write role joins:

```sql
-- per database <db>, connected to <db>, for every schema runs may name
GRANT USAGE ON SCHEMA public TO pgauth WITH GRANT OPTION;
ALTER DEFAULT PRIVILEGES FOR ROLE <db>_service
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO pgauth WITH GRANT OPTION;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO pgauth WITH GRANT OPTION;
ALTER DEFAULT PRIVILEGES FOR ROLE <db>_service GRANT USAGE ON SEQUENCES TO pgauth WITH GRANT OPTION;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO pgauth WITH GRANT OPTION;
-- only with the hardening below (CONNECT revoked from PUBLIC):
GRANT CONNECT ON DATABASE <db> TO pgauth WITH GRANT OPTION;
```

Without them a token with table intent is refused with `the issuer cannot grant …`.

pgauth needs only `ADMIN` on the groups. `INHERIT FALSE, SET FALSE` is the recommendation, so the issuer
login holds none of the groups' rights itself, but it is optional: some tools (for example Terraform /
OpenTofu Postgres providers) cannot express it, and plain `WITH ADMIN OPTION` works too. Temporary roles
get rights only through the groups, so `DROP ROLE` needs no per-database cleanup.

**Optional stats role.** With `statsRole: <role>` on an instance, every temporary role also joins
that role, for example one that holds `pg_read_all_stats` for query statistics. Today everyone with any
access gets it; it is one switch so it can later depend on a scope or binding.

```sql
CREATE ROLE pgauth_stats NOLOGIN;
GRANT pg_read_all_stats TO pgauth_stats;   -- or whatever the stats should allow
GRANT pgauth_stats TO pgauth WITH ADMIN OPTION;
```

**Optional hardening.** pgauth only ever connects a temporary role to the database its token names, so
this is not needed for pgauth to be safe. If no other login relies on `PUBLIC` having `CONNECT`, you can
also keep temporary roles out of other databases at the Postgres level:

```sql
REVOKE CONNECT, TEMPORARY ON DATABASE <db> FROM PUBLIC;
GRANT CONNECT ON DATABASE <db> TO <db>_service, <db>_read, <db>_write; -- plus every other login that uses <db>
```

A role limited to table intent still holds `USAGE` on the named schema and everything `PUBLIC` holds:
`EXECUTE` on functions (including `SECURITY DEFINER` ones, which run as their owner), any table grants
to `PUBLIC`, and `TEMP`. To keep table intent at the declared tables, revoke those in served schemas:

```sql
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE <db>_service REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
-- and grant no table privileges to PUBLIC in schemas pgauth serves
```

## Running

```
pgauth serve --config /etc/pgauth/config.yaml
```

See [`config.example.yaml`](config.example.yaml) for every setting. Upstream `sslmode` takes the libpq
values; `require` encrypts without verifying the server certificate, `verify-ca` / `verify-full` with
`sslrootcert` also verify it. The image
`ghcr.io/lucstr/pgauth:vX.Y.Z` runs as non-root and needs no writable filesystem.

- **Health:** `GET /healthz` answers while the process runs; `GET /readyz` answers 200 once the
  issuer's keys and a valid set of access rules are loaded and every instance passed its self-test;
  its body reports a rejected rules change.
- **Self-test** ([ADR 0014](docs/adr/0014-ready-only-after-a-self-test.md)): at startup (after the owner lock and first sweep) and every `selfTestInterval` (10m),
  pgauth creates `<rolePrefix>_selftest_<pod><random>` with the same statement real temporary roles
  get, in every group the instance can hand out (`<db>_read` and `<db>_write` of every served database,
  plus `statsRole`), logs in as it to every served database and drops it. Until it passes, the
  instance refuses connections. Once ready, it turns not ready only after 3 failed checks in a row
  (retried 1 s apart) and is ready again after one pass; open connections are never touched. Each
  change logs once: `instance ready`, or `instance not ready` with `failures`, the failed `step`
  (`issuer credentials`, `issuer login`, `owner lock`, `sweep`, `self-test: create temp role in every
  group`, `self-test: log in as temp role`, `self-test: drop temp role`) and Postgres's `error`.
  Metrics per `pgauth.instance`: `pgauth.selftest.ok` (1/0), `pgauth.selftest.time` (Unix seconds)
  and `pgauth.selftest.runs` by `result` (`pass`, `fail`). A self-test role left by a crash is swept
  like any dead owner's role.
- **HTTPS API** (`http.listen`, same certificate as Postgres; [ADR 0011](docs/adr/0011-serve-publishes-discovery-and-access.md)):
  - `GET /.well-known/pgauth` → `{postgres, issuer, audience, cli_client_id, scopes: {read, write},
    instances: [{name, databases}]}`, public, so a connector can set itself up from a host name.
  - `GET /v1/access` with `Authorization: Bearer <token>` → `[{instance, database, level}]`: every
    database the token reaches, after the bindings, the scope cap and its authorization details.
  - `GET /v1/tables?db=<instance>/<db>` with a bearer token → `[{schema, table, estimatedRows}]` from
    `pg_class.reltuples` (partitions summed; never-analyzed tables use the live-tuple count), only
    tables `<db>_read` can select, and only the declared ones when the token has table intent; 403 when the token cannot read the database.
- **Audit:** every connection attempt writes one JSON log line and one OpenTelemetry span
  `pgauth.connect` with `sub`, `user`, `groups`, `client_id`, `instance`, `db`, `bindings`, `granted`
  (level from the bindings), `level` (after the cap and authorization details), `scope_cap`, `tables` (`schema.table:verb` when
  the token has table intent), `decision`, `reason`, `role` and duration. Query text is never recorded.
- **Telemetry:** when the standard `OTEL_EXPORTER_OTLP_*` variables are set, spans, metrics and logs
  go out over OTLP with `service.name=pgauth`; `OTEL_LOGS_EXPORTER=none` (or `_TRACES_` / `_METRICS_`)
  switches one signal off. Every log line still goes to stdout as JSON as well, and the connect record
  carries the trace and span ids of its `pgauth.connect` span.

### Replicas and the sweep

Each pgauth process owns the roles it creates ([ADR 0012](docs/adr/0012-each-process-owns-its-roles.md)):
their names and comments carry the process's nonce, and the process holds an advisory lock for it.
Roles are never shared between processes. A role is handed out for half of `maxConnectionAge` and to
at most `roleConnectionLimit` connections, then a new one is made; reusing a role resets its password.

Every `sweepInterval` (1 minute) and at startup, pgauth removes members of `pgauth_temp` that this
process no longer uses, whose owner's lock is gone, or that are older than 1.5 × `maxConnectionAge`
plus 10 minutes. Several replicas are safe; a crashed replica's roles are removed by the next sweep
of any other.

Table groups (`pgauth_t_*`, [ADR 0013](docs/adr/0013-authorization-details-narrow-to-tables.md)) are
permanent: they are not members of `pgauth_temp`, so the sweep never touches them, and nothing drops
them. A temporary role only joins them, and on every connect pgauth re-checks that the binding's group
still holds the verb and that the table group holds what it needs before the temporary role joins it.

Limits before and around authentication:

- Messages before a token is accepted are capped at 64 KiB, and the handshake has 30 seconds.
- `maxConnectionsPerUser` (50) caps one subject's open connections through one pgauth.
- `requireScram` (per instance, default true) refuses any upstream password method but
  SCRAM-SHA-256 before a password is sent, so a server posing as the instance never sees the issuer's
  or a temporary role's password. Set it to false only for a server that cannot do SCRAM.

## Connecting as a person

`pgauth connect` is the connector. It listens on `127.0.0.1:5432` and forwards every client
connection to the right pgauth over TLS, with a fresh token as the password. The database name is
the address ([ADR 0010](docs/adr/0010-database-name-is-the-address.md)):

```
psql "host=127.0.0.1 dbname=prod/order"                # <env>/<db>, the instance is looked up
psql "host=127.0.0.1 dbname=prod/cloudsql-main/order"  # <env>/<instance>/<db>
```

There is no default environment: a bare `order` fails with `use <env>/<db>; environments: prod,
test`, and a name on several instances fails and lists the full addresses. `<env>/<db>` is looked up
in the server's discovery (3 s timeout); the last answer is kept in the user cache directory (or next
to the config), so a short API outage does not break it. With no answer at all the connection fails
with `pgauth api https://<host>:8443 unreachable (<cause>); use <env>/<instance>/<db> to connect
without it`, and `<env>/<instance>/<db>` never needs the API.

1. `pgauth env add prod pgauth.example.com` reads the server's discovery
   (`https://<host>:8443/.well-known/pgauth`), pins its issuer and CLI client in `connect.yaml`, logs
   you in through the browser and lists what you can reach. `--write` asks for the write scope,
   `--ca file` trusts a private CA, `--ide-port` adds an IDE port (below), `--no-login` skips the login. Adding an environment again with a
   different issuer is refused without `--force`.
2. `pgauth connect`, or `pgauth service install` to run it at login (launchd on macOS, a systemd user
   unit on Linux; `service uninstall` removes it).
3. `pgauth ls [env]` lists every database you can reach and your level, from the server's
   `/v1/access`.

`pgauth env list`, `env login <name>` (log in again) and `env remove <name>` (also deletes the
keychain entry) manage environments. `connect.yaml` is `--config`, else `$PGAUTH_CONFIG`, else
`<user config dir>/pgauth/connect.yaml`; see [`connect.example.yaml`](connect.example.yaml) and
[`examples/rapidata-test/connect.yaml`](examples/rapidata-test/connect.yaml).

**Tokens** come from a browser login (authorization code + PKCE; redirect
`http://127.0.0.1:8250/callback`, `callbackPort: 0` for any free port; refresh token in the OS keychain,
one per environment) or from a file that something else keeps fresh (`token: {file, field,
statusFile}`, re-read on every connection). The connector never runs a command
([ADR 0009](docs/adr/0009-tokens-from-login-or-file.md)). A missing, unreadable or expired token file
fails only that connection, with `FATAL 28000` carrying the status file's text (or the path); the next
connection reads the file again. A database without a binding fails with serve's own text, passed through unchanged:
`no access to cloudsql-main/payment for luca@example.com: no binding grants it. <accessHelp>`, where
the server's `accessHelp` says where to ask for access. `pgauth ls` shows the same help when nothing is
reachable.

Any process of yours that can reach the local port connects with your rights, the same trade-off as
other local database proxies.

The v0.4 format (top-level `server`/`issuer`, `listeners` per instance) still loads in v0.5 with a
deprecation warning and stops loading in v0.6.

### IDEs (DataGrip/Rider)

IDEs browse every database in `pg_database` and connect by bare name, which the main port refuses. Give
each environment its own port instead: `pgauth env add prod <host> --ide-port 15432` (or by hand,
`listeners: [{listen: 127.0.0.1:15432, env: prod}]`). On that port `order` and `<instance>/order`
resolve inside prod, and a name of another environment (`test/order`) is refused.

Create one data source per environment on its port, with any user, no password and SSL off. Databases
pgauth does not serve fail with `serves no database`; limit the data source's **Schemas** tab to the
databases you use to keep the IDE quiet.

Binaries for macOS (arm64, amd64) and Linux (amd64, arm64) are attached to each
[GitHub release](https://github.com/LucStr/pgauth/releases). A binary downloaded with a browser
on macOS is quarantined; download it with `curl` or run `xattr -d com.apple.quarantine pgauth`.

## Development

```
go test ./...   # needs Docker: the tests run against postgres:18 through testcontainers
```

Design decisions are in [`docs/adr`](docs/adr) and the vocabulary in [`GLOSSARY.md`](GLOSSARY.md).

## License

Apache-2.0
