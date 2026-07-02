# Operations: running the human-halt unattended

This note covers the operational side of the pending-action lifecycle: how
holds expire without an operator watching, and how an approved action whose
execution was refused gets re-driven. The decision semantics themselves are
specified in `spec/invariants.md` (INV-EXEC-1..4) and are not changed by
anything here.

## Pending-action expiry (TTL)

A routed action halts as a *pending* hold and stays approvable for
`PROM_PENDING_TTL` seconds (default 24h; `0` disables expiry). Three
mechanisms enforce the TTL, layered from most to least authoritative:

1. **The approval-time stale-guard** (authoritative). `approve` re-checks the
   TTL at decision time; a lapsed hold is expired on the spot and the approval
   refused. This holds even if no sweep ever runs.
2. **Opportunistic sweeps** (automatic). The execution controller sweeps
   lapsed holds at its natural touchpoints — when it is constructed, before it
   lists pendings, and before it approves — and the `pending` CLI verb sweeps
   before listing. In normal operation expiry therefore happens without anyone
   scheduling anything.
3. **The explicit `sweep` verb** (scheduled). Idempotent; for deployments
   where holds should expire *promptly* even when nothing else touches the
   controller.

Every expiry, whichever path triggered it, is the same audited transition:
`pending -> expired`, recorded with `decided_by = system:sweep` and visible in
`audit --human-log`.

### Scheduling the explicit sweep

Cron (every 15 minutes):

```cron
*/15 * * * * PROM_LEDGER_PATH=/var/lib/promethyn/ledger.db prometheus-protocol sweep >> /var/log/promethyn/sweep.log 2>&1
```

systemd timer:

```ini
# /etc/systemd/system/promethyn-sweep.service
[Unit]
Description=Expire lapsed Promethyn pending actions

[Service]
Type=oneshot
Environment=PROM_LEDGER_PATH=/var/lib/promethyn/ledger.db
ExecStart=/usr/local/bin/prometheus-protocol sweep
```

```ini
# /etc/systemd/system/promethyn-sweep.timer
[Unit]
Description=Run the Promethyn pending-action sweep every 15 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min

[Install]
WantedBy=timers.target
```

There is deliberately no background thread or daemon inside the runtime: the
opportunistic touchpoints cover normal operation, and unattended deployments
add the scheduler recipe above, without new process-lifecycle complexity.

## Retrying a refused execution (`retry-execution`)

Execution is fail-closed (INV-EXEC-1): if no isolating sandbox is available
when an approval is driven to execution, the approval stands but the execution
is *refused* and recorded. Such a hold — approved, but never executed — can be
re-driven once the sandbox is back:

```console
$ prometheus-protocol retry-execution 7 --by will@driivai.com
retried pending action #7: executed in sandbox 'namespace' (exit 0)
```

`retry-execution` is deliberately narrow:

- It is valid **only** for a hold that is `approved` and has **never**
  successfully executed (its execution was refused fail-closed, or was
  explicitly deferred with `approve --no-exec`).
- It re-drives execution through the **same** gated, sandboxed controller path
  as `approve`. If the sandbox is still unavailable it fail-closes again, and
  that refusal is recorded too.
- It never re-opens the decision. There is no re-approval and no state change
  to the human decision record; a `pending`, `rejected`, or `expired` hold, or
  one that already executed, is refused with a clear error — and that refused
  attempt is itself recorded for audit.

### The retry window

An approval does not authorize execution indefinitely. A retry is accepted
only within `PROM_PENDING_TTL` seconds of the recorded approval
(`decided_at`); after that it is refused, exactly as a lapsed *pending* hold
can no longer be approved. This reuses the existing TTL knob and semantics —
the same duration that bounds how long a hold may wait for a decision also
bounds how long a decision may wait for its execution. `PROM_PENDING_TTL=0`
disables both, and the hold's recorded state is never rewritten by the window:
the human decision stays exactly as it was made.
