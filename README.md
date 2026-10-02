<!-- fleet:header:begin (rendered by `busbar-release plugin sync` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-plane-a2a

First-party signed kind:plane plugin cdylib: the a2a plane, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `plane` | `a2a` | `busbar-plane-a2a-plugin` | 1.6.0 (pinned in `.busbar-ref`) | MIT |

[![ci](https://github.com/GetBusbar/busbar-plane-a2a/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-plane-a2a/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-plane-a2a` is a `kind: plane` busbar plugin.

## Config

Configured under the `a2a` module name.

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
