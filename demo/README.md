# The 5-minute enforcement demo

`run_demo.py` shows Promethyn's enforcement model against the **real** chokepoint
(`prometheus_protocol.chokepoint.BrokeredMigrationRunner`) and a **real**
PostgreSQL. Nothing is mocked. If no database is configured it prints setup
instructions and exits — it never fakes a pass.

## What it shows (watch for this at each step)

| step | what happens | what proves the point |
|---|---|---|
| **1** | An agent, inside the sandbox, tries to reach the DB itself (raw TCP + Unix socket). | Both **BLOCKED**; only `lo` is visible. The agent has **no path** — it can only *propose*. |
| **2** | A verified, approved migration is executed by the runner. | Table absent before, present after: the approved action runs **once**. |
| **3** | The same approval is replayed. | **Refused (`replay`)**; the table still exists exactly once — single-use is real. |
| **4** | A hostile artifact is submitted under a *valid* approval for a different artifact. | **Refused (`artifact_mismatch`)**; the target table survives — the DB is **not touched on a refusal**. |
| **5** | A forged approval (bad signature) is presented. | **Refused (`invalid_signature`)** — the agent has no signing key, so it cannot mint one. |
| **6** | The hash-chained ledger of every decision is printed and verified; then one entry is edited. | `verify_chain()` → **VALID**, then **BROKEN at entry 4** — the receipt cannot be quietly rewritten. |

The load-bearing point across all six: **the agent never holds the credential**,
and only approved / verified / single-use / correctly-bound actions ever run.

## Run it

You need a PostgreSQL the demo can reach, and its credential. Export:

```bash
export PROM_CHOKEPOINT_PG_HOST=127.0.0.1
export PROM_CHOKEPOINT_PG_PORT=55432
export PROM_CHOKEPOINT_PG_DB=appdb
export PROM_CHOKEPOINT_PG_USER=migrator
export PROM_CHOKEPOINT_PG_SCHEMA=public
export PROM_CHOKEPOINT_PG_PASSWORD='...'                 # the credential the RUNNER holds
export PROM_CHOKEPOINT_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export PROM_CHOKEPOINT_APPROVAL_DB=.prometheus/chokepoint-consumed.db  # durable replay state
export PROM_CHOKEPOINT_PG_SOCKDIR=/home/pgproxy/sock      # optional; enables the socket attack in step 1

python demo/run_demo.py
```

Any PostgreSQL the `migrator` role can log into works. Step 1's live isolation
also needs the namespace sandbox (unprivileged user namespaces); where that is
unavailable the demo says so and points at the committed proof
(`tests/chokepoint/test_isolation.py`) instead of pretending.

The runner role must also be able to create `promethyn_internal` and its
`migration_receipts` table when absent. A pre-provisioned deployment can instead
grant `USAGE` on the schema and `SELECT`/`INSERT` on the table. Promethyn writes
the receipt there in the same transaction as the approved migration so a restart
can prove whether the database committed.

Generate `PROM_CHOKEPOINT_KEY` once and keep it in your secret manager. Reuse the
same value across gate and runner restarts; rotating it deliberately invalidates
all outstanding approvals. The command above is for initial setup, not for every
launch.

### A throwaway local cluster (optional, for the strongest step 1)

Placing the socket under a sandbox-hidden path (`/home/<user>/...`) makes step 1
close the Unix-socket path too, not only TCP:

```bash
PGBIN=/usr/lib/postgresql/16/bin          # adjust to your version
useradd -m -d /home/pgproxy pgproxy 2>/dev/null || true
mkdir -p /home/pgproxy/pgdata /home/pgproxy/sock && chown -R pgproxy:pgproxy /home/pgproxy
runuser -u pgproxy -- $PGBIN/initdb -D /home/pgproxy/pgdata -A scram-sha-256 --auth-local=trust -U pgproxy
printf "listen_addresses='127.0.0.1'\nport=55432\nunix_socket_directories='/home/pgproxy/sock'\n" \
  >> /home/pgproxy/pgdata/postgresql.conf
runuser -u pgproxy -- $PGBIN/pg_ctl -D /home/pgproxy/pgdata -l /home/pgproxy/pg.log -w start
runuser -u pgproxy -- $PGBIN/psql -h /home/pgproxy/sock -p 55432 -U pgproxy -d postgres \
  -c "CREATE ROLE migrator LOGIN PASSWORD 'change-me'; CREATE DATABASE appdb OWNER migrator;"
```

Then export `PROM_CHOKEPOINT_PG_PASSWORD='change-me'` (and the vars above) and run
the demo. Only the runner is ever given this password; the sandboxed agent's
context is constructed without it.

## Notes

- The demo uses a fresh in-memory ledger per run, so step 6 shows exactly this
  run's decisions. It cleans up the tables it creates.
- Spent approvals are intentionally different: they live in the durable SQLite
  file named by `PROM_CHOKEPOINT_APPROVAL_DB` (default
  `.prometheus/chokepoint-consumed.db`), so restarting the runner cannot make a
  still-current approval reusable.
- It is deterministic and re-runnable. Each step prints one human-readable
  `STEP N … RESULT` line, so it reads on a screen-share rather than as a log wall.
- This is the enforcement **core** (alpha, one protected action — PostgreSQL
  migrations). The threat model is `docs/chokepoint-threat-model.md`; the ledger's
  tamper-evidence is `docs/ledger-integrity.md`.
