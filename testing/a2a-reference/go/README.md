# Go SDK native-v3 scenario reference

Run ./serve.sh PORT http_json or ./serve.sh PORT jsonrpc. A2AHT_CONTROL_BIN selects the binary directory. Both bindings use native SDK version 1.0 codecs and handlers. SDK pin remains github.com/a2aproject/a2a-go/v2 v2.4.0, source commit 5736cc7c76905476840257b2c3b0f84a6fea8134; module sum h1:da0iwA6voxLhXIw1B3GSAdrhs5UIa2v6m+v/Fix5qTw=; go.mod sum h1:EghJ/rY9OCC6jme1z+otOBf+1YCVVCpMSPZU31t3hKY=. No replacement or patched dependency. New source is based on combined-v2; no oracle, baseline, assertion, or verdict changes.

Application adapters repair observed native results while preserving actual SDK tasks and SDK serialization:
- Store.List represents no matches as an empty task collection rather than null.
- JSON-RPC ingress accepts documented protobuf snake_case parameter spellings alongside lowerCamelCase tags, rejects conflicting aliases, and leaves metadata and arbitrary user data untouched. Fully consumed requests above 4 MiB receive HTTP413, avoiding TCP reset on the measured 8 MiB request.
- Executor preserves a changed-content message when a sender reuses its message ID, retaining exact duplicate idempotency. This addresses the TCK helper which sends different messages sharing one session-scoped message ID; it is generic message handling without prefix-based oracle tuning.
- SendMessage limits its returned task history according to the actual configuration while retaining stored history.
- SubscribeToTask reads real shared SDK-store versions independently of an executor queue's lifetime. Parked input-required tasks remain subscribable until their actual terminal transition; initial and final events are actual stored Task objects, serialized by native SDK streaming code. Existing ingress checks reject unknown/terminal tasks before committing SSE headers. These are actual state checks, not synthetic completion events.
- Public reference calls consistently use the explicitly documented shared public-fixture principal. Optional A2A_REFERENCE_TOKEN uses reference-user. This shared principal is fixture operation, not security qualification.
- Agent cards have representation-derived ETag, stable process-lifetime Last-Modified, Cache-Control max-age, and conditional304 behavior.
- Real SDK HTTP push sender opts into trusted private-network callback delivery via HTTPSenderConfig.AllowPrivateNetworks. This is explicitly a local reference-fixture policy. Default SDK SSRF guarding remains unchanged; actual callback tests preserve bearer and notification-token authentication and SDK StreamResponse payloads. push-v3 red/green evidence records default refusal and configured delivery.

Existing scenario contract, UTC executor timestamps, input validation, protocol version negotiation and Content-Type request rejection remain. No successful backend response is rewritten into a different verdict or fabricated task.

Validation: gofmt; go vet; build; and 15 named targeted test groups covering both transports' real subscriptions, push callbacks, history, aliases/data preservation, task lifecycle, version/null validation, terminal-task errors, oversize HTTP response, and card caching. Parent runs unchanged official TCK and independent native battery. Full suites run in CI.

Source diff against combined-v2 is native-v3/go-v2-to-v3.diff. All packet source files are checksummed in SHA256SUMS. Unknown native failures remain actual failures, never whitelisted.
