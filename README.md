# OwnChain

Scaffold for the OwnChain project. **This repository currently contains
only project scaffolding** — there is no blockchain logic, mining,
wallet, networking, or cryptography implemented yet. Protocol design
lives in [`docs/protocol-v1.md`](docs/protocol-v1.md), where every
undecided parameter is explicitly marked `TBD`.

## Layout

```
ownchain/
├── Cargo.toml            # Package manifest (library + CLI binary, no dependencies yet)
├── src/
│   ├── lib.rs            # Library crate (empty scaffold)
│   └── main.rs           # CLI entry point (prints project identity only)
├── docs/
│   └── protocol-v1.md    # Protocol specification template (parameters: TBD)
└── .github/workflows/
    └── ci.yml            # CI: rustfmt, Clippy, tests
```

## Prerequisites

- [Rust stable toolchain](https://rustup.rs/) (`cargo`, `rustc`),
  including `rustfmt` and `clippy` components:

  ```sh
  rustup component add rustfmt clippy
  ```

## Setup

```sh
cargo build
```

## Run

```sh
cargo run
```

Prints the project name and version, and points to the protocol
specification.

## Test

```sh
cargo test
```

## Lint / format checks

The same checks run in CI (see `.github/workflows/ci.yml`):

```sh
cargo fmt --all -- --check     # formatting
cargo clippy --all-targets -- -D warnings   # lints (warnings are errors)
cargo test --all-targets       # automated tests
```

## Scope and current status

- **In scope for this scaffold:** package structure, docs skeleton,
  Git ignore rules, CI wiring.
- **Not yet implemented (on purpose):** consensus/proof-of-work,
  mining, wallets, networking, cryptography, and any protocol
  dependencies (including RandomX and Orchard). These will be added
  only after the corresponding decisions in `docs/protocol-v1.md`
  stop being `TBD`.
