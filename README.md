# Arnauth

Talk as an email you already own, or as a name you mint. No phone number is
involved anywhere in this codebase.

Arnauth is a small, sovereign desktop client: identities sealed with `wupz`,
keys derived from one seed, messages sealed end-to-end, and a local spool you
point a carrier at. It borrows the *shape* of Arnacon (email-or-identity, no
number) and none of its code — that SDK is a private, store-app package. This is
the "anyone can run their own version" half, written from scratch in Rust.

## Platform support

| Target | CLI `arnauth` | Desktop `arnauth-desktop` |
|--------|---------------|---------------------------|
| macOS (arm64 / x86_64) | yes | yes, native window (winit + glow) |
| Linux (x11 / wayland) | yes | yes, native window |
| Windows | yes | yes, native window |
| FreeBSD / other unix | yes | build from source (winit) |

Nothing is macOS-specific. The only `cfg` split in the whole workspace is file
permissions: `0600`/`0700` on unix, a no-op elsewhere.

## Build and run

```bash
cargo build --workspace          # both binaries
cargo test --workspace           # 122 tests, no network, no fixtures
cargo run -p arnauth-desktop     # the window
cargo run -p arnauth-cli -- --help
```

Binaries land at `target/debug/arnauth` and `target/debug/arnauth-desktop`.

## First five minutes

```bash
arnauth quickstart            # mints nothing, prints the two shapes a label can take
arnauth quickstart kai.eth    # mint, seal, write my-card.json, print next steps
```

Then hand `~/.arnauth/my-card.json` to the other person. They run
`arnauth trust my-card.json` and you can talk. The GUI does the same thing as a
four-step guide that folds each step away once it is done — open it with
`arnauth-desktop`.

## CLI

```bash
arnauth init you@mail.com            # mint, seal, make active
arnauth init kai.eth                 # a name instead of an email
arnauth identities                   # sealed / MISMATCH, active marked with *
arnauth whoami
arnauth card kai.eth > kai.json      # public half only
arnauth trust kai.json               # attest a card: address book + hive
arnauth send kai.eth "no number required"
arnauth inbox --take
arnauth verify                       # re-check every seal, exit 1 on mismatch

# the beehive: learn, share, forget
arnauth swarm show                   # peers by weight, attested vs claimed
arnauth swarm share --out delta.json # attested cards only, sealed
arnauth swarm absorb delta.json      # merge another hive's cards
arnauth swarm forget --half-life-days 30
arnauth swarm receipt                # 64-byte wupz frame over the whole hive

# groups: one cell key, handed out sealed 1:1
arnauth group new saturn.ring
arnauth group add saturn.ring kai.eth
arnauth group invite saturn.ring kai.eth
arnauth group send saturn.ring "one body, every member"
arnauth group list

# media: chunked, content-addressed, resumable
arnauth send kai.eth --file photo.jpg          # 64 KiB chunks, blob id = sha256
arnauth inbox --save ~/Downloads               # reports "3/4 chunks" until whole

# integrations
arnauth webhook add http://127.0.0.1:9000/hook --event message.received
arnauth webhook test                     # signed POST, HMAC-SHA256 over the body
arnauth mcp                              # newline-delimited JSON-RPC on stdio

# relay: one dumb store-and-forward node
arnauth relay serve --bind 127.0.0.1:8795      # memory only, no disk, no logs
arnauth send kai.eth "hi" --via 127.0.0.1:8795
arnauth inbox --via 127.0.0.1:8795             # GET drains the queue
```

The store root is `$ARNAUTH_HOME`, then `~/.arnauth`:

```text
~/.arnauth/
├── active                       label of the identity opened by default
├── beehive.json                 peers, weights, cells (0600: holds cell keys)
├── contacts.json                address book
├── identities/<label>/
│   ├── identity.json            sealed row
│   └── key.bin                  32-byte seed, 0600
└── transport/<dh-public>.jsonl   spool queue per recipient
```

## How the pieces fit

| Concern | Implementation |
|---------|----------------|
| Who you are | `arnauth-core::identity` — a label is classified as email or name, normalized, and hashed into a stable subject |
| Tamper evidence | `arnauth-core::seal` — the identity row is packed into balanced ternary (`{-1,0,+1}`, 5 trits/byte) inside a fixed `wupz` arena, then folded into a `0x62`-gated 32-byte frame |
| Keys | `arnauth-core::keys` — one seed, HKDF-SHA256 with separate info strings for Ed25519 and X25519 |
| Messages | `arnauth-core::envelope` — ephemeral X25519 → HKDF → ChaCha20-Poly1305, with an Ed25519 signature over header + ciphertext |
| Storage | `arnauth-core::store` — one directory per identity, `0600` seed, seal re-checked on every load |
| Address book | `arnauth-core::contacts` — public cards only, subject must match the label it claims |
| Transport | `arnauth-core::transport` — a directory of JSONL queues keyed by recipient DH public key |
| The graph | `arnauth-core::beehive` — peers with decaying weight, cells, sealed deltas, and a 64-byte `LitanyWireFrame` receipt over the whole hive |
| Groups | `arnauth-core::group` — one ChaCha20 key per cell, encrypted body once, key handed to each member as a 1:1 `KeyWrap` |
| Payload types | `arnauth-core::payload` — a one-byte tag on the plaintext: text, group key handoff, group message |
| Post-quantum | `arnauth-core::pq` — hybrid X25519 + ML-KEM-768 establishment and Ed25519 + ML-DSA-65 signatures (FIPS 203/204), wired into envelopes as `mode: hybrid` |
| Media | `arnauth-core::media` — 64 KiB chunks, `blob_id = sha256(domain‖len‖content)`, per-chunk hashes, resumable staging (`ChunkStore`) |
| Relay | `arnauth-core::relay` — TCP store-and-forward, queues in memory, bounded, drains on read, no disk and no logs |
| Webhooks | `arnauth-core::api` — `http://` only, HMAC-SHA256 signature header, failures logged and swallowed |
| Agents | `arnauth mcp` — MCP over stdio, six tools, tool errors as results not crashes |

`wupz` is used for what it actually is: a fixed-arena ternary pack plus a
deterministic frame. It is not standing in for a signature; the Ed25519
signature does that, and the seal does something the signature cannot — it fails
loudly if the row on disk was edited by hand.

## The beehive: learn, share, forget

Nothing is kept merely because it was once written.

- **Learn** — a card you import or hear again gains weight. `trust` attests a
  card out of band; a card reconstructed from an envelope is marked `claimed`,
  because a signature proves a key, not a name.
- **Share** — `swarm share` exports **attested cards only**, sealed. Weights,
  history, and cell keys never travel, and a `claimed` label is never forwarded:
  doing so would launder someone else's claim into your attestation.
- **Forget** — weight halves once per half-life of silence (30 days by default)
  and anything under the floor is dropped. Cells lose members that are gone.

`swarm receipt` folds the whole hive into one 64-byte `0x62`/`qt:55` frame, so
two machines can compare state in one comparison instead of diffing JSON.

## Groups

One symmetric key per cell, handed to each member sealed 1:1. A group body is
encrypted **once** with the cell key and that same ciphertext is wrapped in a
per-member envelope, so a cell with 40 members costs 40 signatures but one
encryption.

Honest limits: a member who leaves keeps the key for everything already sent,
and membership changes do not rekey the cell yet.

## Post-quantum, honestly

`pq.rs` implements both hybrid upgrades and they are covered by tests:

```
ml_kem_ciphertext_size_is_fips_203   ok   1088-byte ct, 1184-byte ek
pq_signature_sizes_are_fips_204      ok   1952-byte vk, 3309-byte sig
hybrid_kem_agrees_across_sides       ok
hybrid_signatures_need_both_halves   ok   either half failing rejects
```

What that buys: an attacker must break **both** X25519 and ML-KEM-768 to read a
message, and both Ed25519 and ML-DSA-65 to forge one.

How it is negotiated: a contact card carries an optional `pq` half. A peer with
one gets `mode: hybrid`; a peer without gets `classical`. A hybrid envelope is
**never** silently downgraded — an identity with no PQ keys refuses to send to a
PQ peer rather than quietly going classical, and a classical-only recipient
cannot open one.

What it does not buy: Ethereum transaction signatures are secp256k1 and stay
that way until a PQ precompile or an ERC-4337 account with a PQ verifier exists.
"Quantum-proof" without that sentence is a lie. See `docs/web3-design.md`.

## Integrations

Two outward faces, by design.

**Webhooks** for systems:

```bash
arnauth webhook add http://127.0.0.1:9000/hook --event message.received
# every delivery carries:
#   X-Arnauth-Signature: <hex hmac_sha256(secret, body)>
# body: {"event":"message.received","payload":{...},"protocol":"arnauth.webhook.v1"}
```

Only `http://` with an explicit port is accepted — there is no TLS stack in this
crate, and saying so beats failing mysteriously. A dead endpoint is logged and
swallowed; it never stops a message from being read.

**MCP** for agents. `arnauth mcp` is the whole integration surface: the tool
process runs as you, so it *is* the credential. Six tools —
`arnauth_whoami`, `arnauth_identities`, `arnauth_peers`, `arnauth_send`,
`arnauth_inbox`, `arnauth_receipt` — over newline-delimited JSON-RPC on stdio.

```jsonc
{"mcpServers":{"arnauth":{"command":"arnauth","args":["mcp"]}}}
```

## Design

- `docs/web3-design.md` — interface principles, chain architecture, contract
  sketches, VAKED/FOKEN placement, monetization surfaces, build order, threat model
- `brand/ui-mock.html` — a self-contained mock of the target interface in the
  `ultralovegod` palette. Open it in a browser; ⌘K works.

## What is deliberately not here

- **No network transport.** No relay, no push, no WebSocket. `transport` is a
  local spool; writing a carrier is a separate job and out of scope here.
- **No media transport.** Envelopes carry bytes without a size limit, but there
  is no chunking, streaming, or blob store yet.
- **No calls or audio.** Envelopes carry bytes, not media streams.
- **No Arnacon SDK.** `cellact/Arnacon-iOS-SDK` and
  `cellact/Arnacon_Android_Client_OpenSource` are private, and Arnacon's own MCP
  is a spec with `liveServer: false`. See `../wa-stream/arnacon/README.md`.
- **No key escrow.** Lose `key.bin`, lose the identity. That is the point.
- **No chain calls.** No contract, no wallet, no ENS, no payment. `pq.rs` is the
  only web3-adjacent code, and it is cryptography, not a transaction.

## Security notes

- `key.bin` is the identity. It is written `0600` and never logged.
- The seal detects hand-edits; it does not defend against an attacker who can
  also rewrite the seal and the row together. The signature inside each envelope
  is what binds a *message* to a senders' key.
- Envelope headers are cleartext (who → whom, epoch). Only the body is sealed.
- `send` refuses to use keys that do not match the sender identity, so one
  identity cannot sign as another.

## Licence

AGPL-3.0-only, matching `wupz-core`, which this crate links.

## Where this is going

The target shape is Discord + WhatsApp with a Telegram streak: unlimited
history, groups, DMs, honest auth, media, and an identity that is not a phone
number.

| Feature | State |
|---|---|
| DMs | working (`send` / `inbox`) |
| Groups | working, sender-key cells (`group`) |
| No message limit | envelopes carry arbitrary bytes; the spool is a file, so the limit is your disk. No pagination or retention policy yet |
| Honest auth | entered: keys are Ed25519, bindings are signed, seals catch edits. A label claim is only `claimed` until attested out of band |
| Media | **not yet** — no chunking, no blob store, no streaming |
| Virtual or real phone number | deliberately absent. Nothing in this codebase needs a number |
| Carrier / relay | **not yet** — the spool is a directory you move yourself |
| Multi-device | not yet — a store is one device, the seed is the identity |
| Voice and video | not yet |

Each row is a separate slice with its own tests. The next honest ones are media
chunking, a relay, and rekey-on-leave for cells.
