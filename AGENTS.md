# AGENTS.md — `arnauth`

Rust workspace. Two binaries over one library:

- `crates/arnauth-core` — identity, wupz seal, keys, envelopes, payload tags, store,
  contacts, spool, beehive (learn/share/forget), groups (cell keys), pq (hybrid
  FIPS 203/204 primitives)
- `crates/arnauth-cli` — `arnauth`
- `crates/arnauth-desktop` — `arnauth-desktop` (eframe)

## Commands

```bash
cd ~/workspace/peterlodri-sec/arnauth
cargo test --workspace         # 105 tests, offline
cargo clippy --workspace --all-targets
cargo fmt --all
cargo run -p arnauth-desktop
```

Smoke test with a throwaway store:

```bash
export ARNAUTH_HOME=/tmp/arnauth-smoke && rm -rf $ARNAUTH_HOME
./target/debug/arnauth init you@mail.com
./target/debug/arnauth init kai.eth
./target/debug/arnauth send kai.eth "hello" --from you@mail.com
./target/debug/arnauth use kai.eth && ./target/debug/arnauth inbox --take
./target/debug/arnauth card kai.eth > /tmp/kai.json && ./target/debug/arnauth trust /tmp/kai.json
./target/debug/arnauth group new ring.one && ./target/debug/arnauth group invite ring.one kai.eth
./target/debug/arnauth swarm show && ./target/debug/arnauth swarm receipt

# v1 surface: hybrid + media + relay
./target/debug/arnauth send kai.eth --file /tmp/photo.jpg
./target/debug/arnauth inbox --save /tmp/dl
./target/debug/arnauth relay serve --bind 127.0.0.1:8795 &   # then:
./target/debug/arnauth send kai.eth "hi" --via 127.0.0.1:8795
./target/debug/arnauth inbox --via 127.0.0.1:8795
```

## Rules

- **`key.bin` is the identity.** Never log it, never copy it into a test fixture,
  never widen 0600.
- **The seal is not a signature.** Do not describe `seal_row` as authentication;
  the Ed25519 signature in `envelope` carries that weight. Keep the README honest
  about the split.
- **`share` exports attested cards only.** A `claimed` peer is one reconstructed
  from an envelope: the signature proves the key, not the name. Forwarding a
  claim would launder it into someone else's attestation — there is a test for
  this and it must stay passing.
- **Forgetting must stay deterministic.** `forget` is a pure function of the
  clock and the stored `last_seen_ms`. Do not introduce wall-clock reads inside
  it; the argument `now` is the only time source.
- **Group keys are per-cell.** A new membership is a key handoff, not a list
  edit. If rekey-on-leave ever lands, it needs its own module and tests.
- **`pq.rs` is unwired on purpose.** Do not bolt it into `Envelope` without
  shipping `envelope.v2` and a capability negotiated in the contact card; v1
  messages must keep opening. Do not describe the product as "quantum-proof"
  without the on-chain caveat in `docs/web3-design.md` §2.3.
- **No invented rails.** There is no network transport. If a caller wants one,
  it goes through `transport::Spool` or a new module with its own tests, not into
  a fake `send`.
- **Row layout is versioned.** Changing `identity::Identity::row` requires a new
  `seal::ROW_DOMAIN` string and a protocol bump, otherwise old seals silently
  stop verifying.
- **Platform parity.** The only `cfg` split is file permissions. Do not add
  macOS-only code paths; eframe/winit covers macOS, Linux, and Windows.
- **`wupz-core` is a path dependency** (`../wupz/wupz-rs`). Its `build.rs` links
  the Zig kernels when `zig` is on PATH and falls back to the scalar fold when it
  is not, so a contributor without Zig is not blocked.

## Design and web3

- `docs/web3-design.md` — the design/architecture note. Monetization surfaces in
  it are marked **unverified**; do not quote them as live.
- `brand/ui-mock.html` — static mock, no build step, no dependencies. Keep it
  self-contained and keep the palette tokens from `design.vaked.dev`.

## Where the Arnacon context lives

`../wa-stream/arnacon/README.md` records why there is no Arnacon SDK to link
against (private repos, spec-only MCP). Read it before anyone promises "Arnacon
support".
