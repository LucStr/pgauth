# pgauth

Scoped access to Rapidata's Postgres databases: who may read or write which database, decided and enforced by pgauth from role bindings.

## Language

**Database grant**:
The right to read or write one Postgres database or a whole instance, written as a grant of a `PgRole`. Any account can be bound to one, not only staff.
_Avoid_: permission, access right, ACL

**Built-in role**:
A `PgRole` pgauth provides without YAML: `pg-admin` (write everywhere), `pg-reader` (read everywhere) and the generated `<instance>.<db>.read|write` for every configured database.
_Avoid_: default role, system role

**Role binding**:
A `PgRoleBinding` that gives one `PgRole`'s database grants to users and groups named in the token.
_Avoid_: assignment, membership

**Database scope**:
The OAuth scope `postgres:read` or `postgres:write` a token was issued with; pgauth caps the access from role bindings by it. Vessels hold `postgres:read`; `postgres:write` is only issued inside an approved write run.
_Avoid_: agent ceiling, agent limit

**Database token**:
A short-lived token for the Postgres audience that proves who the holder is (user and groups) and carries a database scope; it lists no grants, though its authorization details may narrow them.
_Avoid_: JWT, access token, credential

**Authorization details**:
Rows in a database token that narrow access below the role bindings and the database scope, never above: consent rows per database, and table intent for one run.
_Avoid_: RAR, permissions claim, token grants

**Consent row**:
An authorization detail a person chose for their agents: read or write on every database (`*`) or on one database. The row naming one database wins over `*`.
_Avoid_: override, database scope

**Table intent**:
The tables and verbs (select, insert, update, delete) a run declares for one database; with it, that database reaches only those tables.
_Avoid_: table scope, run scope, table grant

**Table group**:
A group role that carries one verb on one table, shared by every temporary role that needs it and never dropped.
_Avoid_: table role, per-table grant

**pgauth**:
The proxy that accepts a database token as a Postgres password and connects on the holder's behalf.
_Avoid_: pg-gate, proxy, gateway

**Temporary role**:
A Postgres login pgauth creates for one holder and set of rights, and drops when the holder's last connection closes.
_Avoid_: temp user, ephemeral user, dynamic credential

**Self-test**:
The check that gates an instance's readiness: pgauth creates a temporary role joined to every group role, logs in as it to every served database and drops it, at startup and every `selfTestInterval`.
_Avoid_: health check, probe, smoke test

**Group role**:
A Postgres role, one per database and level, that carries the actual table privileges a temporary role joins.
_Avoid_: db role, permission role

**Gate check**:
The one moment access is decided: when a connection opens. An open connection is not re-checked.
_Avoid_: session check, re-validation

**Connector**:
The local program a person runs (`pgauth connect`) that logs them in through the browser and lets any Postgres client reach pgauth through `localhost`.
_Avoid_: helper, CLI, local proxy

**Environment**:
One pgauth deployment a connector reaches, such as prod or test, with its own server and token source. It is the first segment of a database address.
_Avoid_: profile, context, cluster

**Database address**:
The database name a client asks the connector for: `<env>/<db>` or `<env>/<instance>/<db>`. There is no default environment.
_Avoid_: DSN, connection name

**Instance**:
One Postgres server pgauth can reach, such as the main Cloud SQL or the bidder cluster's Postgres. Database names are only unique within an instance.
_Avoid_: server, cluster, host
