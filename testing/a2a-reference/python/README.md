# Python reference fixture

Declared local fork of the Busbar TCK scenario executor, running the published a2a-sdk==1.1.2 package. This is a server fixture, not an unmodified upstream SDK sample. It advertises one JSONRPC 1.0 interface, streaming and push notifications; it does not claim gRPC, HTTP+JSON, client or seam coverage.

The executor retains published in-band TCK scenario behavior. Ordinary requests complete a task. SDK JSON serialization, SSE, push delivery and storage remain in use. Four deliberate local repairs are part of this reference implementation:

- Validate malformed message JSON shapes before protobuf coercion; unknown numeric roles and null parts are rejected.
- Project ListTasks artifacts out of JSON entirely by default or when includeArtifacts=false. The SDK dispatcher otherwise reinserts empty arrays after its handler clears the protobuf field. Explicit true preserves actual stored artifacts.
- Disable v0.3 compatibility. Absent/empty A2A-Version means 0.3 and receives VersionNotSupportedError. Only 1.0 (optionally patch) is served.
- Reject further messages on terminal tasks with UnsupportedOperationError before SDK history mutation. SDK 1.1.2 already refuses them but uses InvalidParamsError.

Upstream faults remain upstream faults: this fixture does not establish that unmodified SDK 1.1.2 passes these cases. No battery expectations or shared controls are modified. Errors outside the repaired boundary remain measurable.

Run `A2A_REFERENCE_PYTHON=/path/to/python ./serve.sh PORT`. The interpreter must contain exactly a2a-sdk==1.1.2 and dependencies from the copied requirements.txt lock (install with --require-hashes). PROVENANCE.json identifies the fork input and hash.
