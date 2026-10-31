<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-plane-a2a

First-party signed kind:plane plugin cdylib: the a2a plane, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `plane` | `a2a` | `busbar-plane-a2a-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-plane-a2a/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-plane-a2a/actions/workflows/ci.yml)
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
  - `agents.<name>.protocol_version`: accepted, read by nothing.
  - `agents.<name>.allow_private`: may the agent live on a private or loopback address (default
    `false`).
  - `agents.<name>.upstream_credentials`: the outbound credential mode (`passthrough` is refused).
  - `agents.<name>.upstream_credential`: the leased credential busbar presents on the hop (a
    secret-store handle and its lease policy).
  - `agents.<name>.egress_scopes`: refused (nothing in this build enforces it).
  - `agents.<name>.hooks`: hooks attached to this agent, added to `agents.hooks`.
  - `agents.hooks`, `agents.upstream_credentials`: the all-agents hooks and credential default.
- `pools:` (the top-level failover pools whose members are `agents:` registrations): handed to the
  plane under `agents:`, first member the primary.
- `agent_push:` (the plane's own section, read at open and re-judged at every reload): `ca`, the
  operator CA (PEM) push callbacks are verified against. Absent = off.

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
| `BUSBAR-7104` | `plane-sse-frame-not-utf8` | actionable |

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
