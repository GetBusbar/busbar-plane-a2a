<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-plane-a2a

First-party signed kind:plane plugin cdylib: the a2a plane, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `plane` | `a2a` | `busbar-plane-a2a-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

<!-- fleet:header:end -->

## What it is for

`busbar-plane-a2a` is busbar's `kind: plane` plugin for the Agent2Agent (A2A) protocol. It fronts
the external A2A agents an operator registers: callers reach each agent through busbar on the
protocol's three lines (JSON-RPC, HTTP+JSON and gRPC, mounted under `/a2a`), busbar verifies each
agent's card against an operator-supplied trust root, and every hop is governed, metered and
audited by the kernel. It also serves busbar's own agent card and A2A push notifications. The
plane opens no socket of its own: its hops ride the host's `http` and `grpc` needs.

## Config

Off by default: a document with no `agents:` section states no route.

- `agents:` (the section the plane declares): one entry per registered agent, by name, plus two
  reserved section-level keys.
  - `agents.<name>.url`: the agent's real A2A endpoint (never shown to callers).
  - `agents.<name>.pin`: the trust root, required: `mechanism` (`unpinned` spelled out when none),
    `key`, `fingerprint`.
  - `agents.<name>.client_identity`: the client certificate busbar presents (`cert`, `key`, secret
    references); required under `pin.mechanism: mtls`.
  - `agents.<name>.reverify_ttl`: the longest a card verification is reused (default `5s`).
  - `agents.<name>.recovery_backoff`: how long after a drift a clean answer is disbelieved.
  - `agents.<name>.protocol_version` is unsupported and refused. Remove this field; supported
    protocol versions are negotiated on the wire.
  - `agents.<name>.allow_private`: may the agent live on a private or loopback address (default
    `false`).
  - `agents.<name>.upstream_credentials`: the outbound credential mode (`passthrough` is refused).
  - `agents.<name>.upstream_credential`: the leased credential busbar presents on the hop (a
    secret-store handle and its lease policy).
  - `agents.<name>.egress_scopes`: non-empty lists are refused because nothing enforces this
    control in this build; omit it or use an empty list.
  - `agents.<name>.hooks`: hooks attached to this agent, added to `agents.hooks`.
  - `agents.hooks`, `agents.upstream_credentials`: the all-agents hooks and credential default.
- `pools:` (the top-level failover pools whose members are `agents:` registrations): handed to the
  plane under `agents:`, first member the primary.
- `agent_push:` (the plane's own section, read at open and re-judged at every reload): `ca`, the
  operator CA (PEM) trusted when making outbound callback deliveries. When absent, deliveries trust
  the platform public roots; omitting this section does not disable configured callbacks.

## Request size policy

A2A operation request bodies are limited to **256 KiB (262,144 bytes)**. Larger bodies
are refused before JSON or protobuf decoding, task creation, and backend dispatch,
with HTTP 400 / JSON-RPC `-32602` (gRPC `INVALID_ARGUMENT`) and an explicit limit message.
The request id is unread and therefore null. The ceiling applies to the raw body on each
binding and to the composed JSON request; an expanded REST/protobuf representation can
also exceed it. Card and discovery reads are excluded. This local capacity policy is
independent of the A2A specification, which defines no fixed message-size ceiling.

The existing **512 KiB backend reply limit** and watchdog budgets are unchanged.
The smaller request bound limits parsing work and leaves room for ordinary task history
and response framing; it does not guarantee that arbitrary backend output will fit.
Large content should be supplied by file URL instead of inline parts. Admission checks
precede body decoding; an oversized malformed body is refused for size.

## Diagnostics

The codes this plane raises (stated in `plane-a2a/declares.json`):

| code | slug | severity |
|---|---|---|
| `BUSBAR-2030` | `a2a-task-chain-verify-failed` | actionable |
| `BUSBAR-7003` | `a2a-pool-not-interchangeable` | benign_recurring |
| `BUSBAR-7013` | `a2a-outbound-cred-unleased` | actionable |
| `BUSBAR-7018` | `a2a-relayed-stream-refused` | benign_recurring |
| `BUSBAR-7020` | `a2a-relayed-outcome-unrecorded` | actionable |
| `BUSBAR-7021` | `a2a-relayed-submission-failed` | benign_recurring |
| `BUSBAR-7023` | `a2a-failure-unrecorded` | actionable |
| `BUSBAR-7024` | `a2a-task-rows-unreadable` | actionable |
| `BUSBAR-7025` | `a2a-task-state-unread` | actionable |
| `BUSBAR-7031` | `a2a-split-record-unread` | actionable |
| `BUSBAR-7032` | `a2a-split-record-stray-parts` | benign_recurring |
| `BUSBAR-7040` | `a2a-backend-task-id-unheld` | actionable |
| `BUSBAR-7041` | `a2a-relay-endpoint-refused` | actionable |
| `BUSBAR-7042` | `a2a-trust-sighting-unrecorded` | actionable |
| `BUSBAR-7044` | `a2a-card-record-unread` | actionable |
| `BUSBAR-7045` | `a2a-hook-rewrite-not-applied` | actionable |
| `BUSBAR-7046` | `a2a-hook-rewrite-unreadable` | actionable |
| `BUSBAR-7050` | `a2a-push-check-unavailable` | actionable |
| `BUSBAR-7104` | `plane-sse-frame-not-utf8` | actionable |

## Request rewrites and served cards

A committed request-hook rewrite must produce a JSON params object. An empty messages list or
plain text such as `[REDACTED]` refuses the submission; the original params are not relayed.
Fronted cards omit explicitly advertised interface versions outside the supported `0.3` and
`1.0` families, and a card with no servable interface is refused.

## Active task capacity and upgrades

Each instance admits at most 4096 active tasks, with the same 4096 bound per
principal. Admission, the task row, both genesis events and any inline push
configuration commit atomically. The first terminal transition releases capacity
in that same transaction. Completed tasks remain readable under the existing
terminal retention policy. A capacity refusal creates no task, events or push
configuration and answers `503` with `active task capacity reached`.

Quota metadata lives in the declared `task_quota` record kind alongside task
records. Preserve it in backups and restores; do not delete or independently
repair its counters. Normal restarts retain the counters and need no bootstrap
grant. Missing, malformed or inconsistent metadata refuses mutations rather than
resetting capacity.

A store created before quota accounting requires a cold upgrade. Stop every
writer sharing the instance and store, settle all previously admitted writes,
and supply the host's instance/store-bound cold bootstrap receipt. The host must
attest this barrier through its reserved `record-quota-bootstrap:` capability;
an ordinary principal grant cannot authorize it. Without that host proof this
build refuses initial bootstrap, including on an empty store. A hot generation
reload does not establish quiescence.

Bootstrap holds a durable initializing gate, reconstructs principal counters in
bounded transactions, then activates the complete instance count. Interrupted
bootstrap can resume with a newly authorized cold host; a stale initializer
cannot overwrite activated accounting. Existing active tasks above the bound
are preserved and may complete or cancel, while new admissions remain refused.
Unparseable rows or a listing exceeding the host's bounded scan capacity refuse
bootstrap; such legacy stores require an offline migration, with no claim that a
partial listing is sufficient. The active-task limits do not impose a separate
byte or event-history quota.

## Build

```bash
cargo build --release -p busbar-plane-a2a-plugin
```

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
