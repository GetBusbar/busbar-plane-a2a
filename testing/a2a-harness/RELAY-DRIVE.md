# Correlated relay driver contract

`--client-drive` remains the client-role driver. It does not prove the relay seam.
The additive `--relay-drive COMMAND` configures delegation on the same running
subject selected by `--endpoint` or `--launch`. No implementation is named in the
harness and there is no default adapter or inferred setup API.

Example (the operator supplies this adapter):

```
--relay-drive 'my-configure-command --upstream {endpoint} --downstream {url}'
```

The harness splits COMMAND into arguments with `shlex.split`, then substitutes:

| Placeholder | Value |
|---|---|
| `{endpoint}` | Existing subject base URL |
| `{url}` | Fresh harness-controlled downstream peer base URL |
| `{card_url}` | Downstream well-known agent card URL |

The command must configure the running subject to delegate the next upstream
SendMessage to that downstream peer and exit zero within 20 seconds. It may
fetch the downstream card, but must not create tasks or send other operations.
Its output is discarded, never used as a response or verdict. It inherits the
configured working directory and environment. Authentication/configuration of
the subject remains the adapter's responsibility; no target-specific endpoint
is assumed. The adapter must not leave background processes running. A fixture
should keep this routing setting scoped to its own test lifetime.

After configuration exits, the harness generates two fresh random challenges.
It sends one in an upstream SendMessage with `configuration.blocking=true`,
directly over the target's advertised HTTP+JSON or JSONRPC binding, using the
configured auth headers and TLS policy. The other challenge is present only in
the fake downstream response, not the upstream request or driver arguments.
The subject must relay request text and return the downstream response text in
upstream task artifacts. The harness observes, rather than trusts an adapter's
report of, exactly one downstream SendMessage and task, the upstream challenge
in that downstream request, and the downstream-only challenge in the upstream
completed task. JSONRPC responses must match the exact request ID and contain
one result without an error. Duplicate JSON members are refused.

Missing configuration, command failure/timeout, upstream failure/timeout,
missing or duplicate downstream sends/tasks, mismatched challenges, malformed
upstream tasks, nonterminal tasks, and uncorrelated JSONRPC responses produce
NOT_CONFIGURED. These are failures to establish the bounded measurement, not
invented protocol MUST violations. Only after establishing correlation does the
existing seam row assert separately generated upstream/downstream task and
context IDs and absence of upstream identifiers in the downstream request.
Identifier leaks produce FAIL. No roles are hidden or automatically selected.

This first contract is deliberately a unary, blocking, text-preserving task
profile. A legitimate relay that returns Message, streams, transforms away all
challenge text, or completes asynchronously needs a future observable contract;
it cannot earn a seam pass here. The upstream operation runs in a disposable spawned process with a 20-second
wall-clock deadline, including worker startup and response transfer to a private
result file. Expiry terminates and reaps the worker (up to two additional seconds
for terminate/kill cleanup), so an endlessly trickling response cannot hold the
harness indefinitely. Private result files are removed on every exit. It does not
claim to detect downstream work scheduled after the upstream response has
completed. Those limitations are not converted into passing observations.

Run the targeted wire controls with:

```
python3 testing/a2a-harness/scripts/relay-drive-selftest.py -v
```

The local relay control uses genuine HTTP request/response flows to prove the
positive and negative measurement paths. It is not an SDK implementation and
its green result is not SDK or subject conformance evidence. SDK/subject runs
remain server-only until their real client driver and relay configuration
adapter execute all required rows successfully. CI owns the full suites.
