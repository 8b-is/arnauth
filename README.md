# Arnauth

**A messenger that doesn't need your phone number, and doesn't need to trust a server.**

---

## The five-year-old version

Imagine you have a **special key** and a **locked box**.

- You write a note and put it in the box.
- You lock it with *your friend's* key — the lock that only their key opens.
- You hand the box to a courier. The courier can't open it. The courier doesn't
  even need to know who it's for.
- Your friend opens it with their key.

That's it. That's the whole app.

- A **courier** is anything that moves boxes: a folder, a USB stick, a small
  program you run, whatever. Arnauth does not care.
- Your **name** is your email, or a name you invent (`kai.eth`). Not a phone
  number. Nobody asks for a number, ever.
- The **lock** is maths that even a future quantum computer shouldn't break —
  two locks, actually, one old and one new, so if either breaks you are still
  fine.

And because there is no server, nobody can read your notes, sell them, or
"temporarily suspend your account". There is no account.

## The grown-up version

| You want | Arnauth does |
|---|---|
| No phone number | identity is an email or a minted name |
| Nobody reads your messages | hybrid X25519 + ML-KEM-768 seals the box |
| Proof of who sent it | hybrid Ed25519 + ML-DSA-65 signs it |
| No server to trust | a dumb courier moves sealed boxes; it cannot read them |
| Big files | 64 KiB chunks, content-addressed, resumable |
| A group chat | one key per group, handed to each member sealed 1:1 |
| Agent / bot access | MCP over stdio — six tools |
| Integrations | signed webhooks, or plugins that react to events |

## Try it in 60 seconds

```bash
arnauth quickstart kai.eth          # mint an identity, print next steps
arnauth card kai.eth > my-card.json # share this file however you like
```

The other person runs `arnauth trust my-card.json`, then:

```bash
arnauth send kai.eth "hello from a key, not a phone number"
arnauth inbox --take
```

Prefer a window? `arnauth-desktop` opens the same store as a four-step guide on
first run.

## Install

```bash
cargo build --release --workspace
ln -sf "$PWD/target/release/arnauth"          ~/.local/bin/arnauth
ln -sf "$PWD/target/release/arnauth-desktop"  ~/.local/bin/arnauth-desktop
```

macOS, Linux, and Windows all build; the only platform-specific code in the
whole workspace is file permissions (`0600` on unix, a no-op elsewhere).

## Everything the CLI does

```bash
# identity
arnauth quickstart [label]      arnauth init <label>       arnauth identities
arnauth whoami                  arnauth use <label>        arnauth verify
arnauth card <label>            arnauth trust <card>       arnauth seal [label]

# talking
arnauth send <to> "text"        arnauth send <to> --file photo.jpg
arnauth inbox [--take] [--save DIR]
arnauth broadcast "text" --peers --channel saturn.ring
arnauth broadcast "text" --to kai.eth --to nova.eth

# groups
arnauth group new <name>        arnauth group add <cell> <member>
arnauth group invite <cell> <member>                arnauth group send <cell> "text"
arnauth group list

# the beehive (who you actually talk to, and forgetting)
arnauth swarm show              arnauth swarm share --out delta.json
arnauth swarm absorb <file>     arnauth swarm forget --half-life-days 30
arnauth swarm receipt

# moving boxes
arnauth relay serve --bind 127.0.0.1:8795
arnauth send <to> "hi" --via 127.0.0.1:8795
arnauth inbox --via 127.0.0.1:8795

# integrations
arnauth webhook add http://127.0.0.1:9000/hook --event message.received
arnauth webhook list              arnauth webhook test
arnauth plugin add <name> --command /usr/bin/say --arg hi --event message.received
arnauth plugin list               arnauth plugin test <name>
arnauth mcp
```

## How it actually works

| Concern | Module | What it does |
|---|---|---|
| Who you are | `identity` | label → normalised → subject hash; sealed with a wupz integrity frame |
| Integrity check | `seal` | row packed into balanced ternary, folded into an unkeyed 32-byte `0x62` frame |
| Keys | `keys` | one seed, HKDF-split into Ed25519 (who) and X25519 (who can read) |
| Messages | `envelope` | ephemeral X25519 + ML-KEM-768 → HKDF → ChaCha20-Poly1305, signed by both halves |
| Files | `media` | 64 KiB chunks, `blob_id = sha256(domain‖len‖content)`, per-chunk hashes, resumable staging |
| Courier | `transport`, `relay` | a local spool folder, or a TCP node that stores nothing and logs nothing |
| Groups | `group` | one ChaCha20 key per cell, body encrypted once, key wrapped per member |
| Channels | `payload` | tag `0x05`: one body, many individually sealed envelopes |
| The graph | `beehive` | peers with decaying weight, learn / share / forget, 64-byte hive receipt |
| Integrations | `api`, `plugin` | HMAC-signed webhooks; plugins are commands with the event on stdin |
| Agents | `arnauth mcp` | JSON-RPC over stdio, six tools, errors as results |

### The trust ladder

Every conversation shows four independent facts, never one "verified" badge:

| Rung | Means |
|---|---|
| `claimed` | their key is proven by a signature; their *name* is not |
| `attested` | you imported their card out of band |
| `sealed` | the identity row passes its wupz frame |
| `hybrid` | both Ed25519 and ML-DSA-65 verified |

### Negotiation, not downgrade

A card with a `pq` half gets a hybrid envelope; a card without gets classical.
A PQ-capable sender talking to a classical-only identity **errors** rather than
quietly going weak.

### Post-quantum, honestly

Off chain, messages are hybrid by default. On chain, Ethereum transaction
signatures are still secp256k1 and will be until a PQ precompile or an ERC-4337
account with a PQ verifier exists. Anyone saying "quantum-proof web3" without
that sentence is selling something.

## Integrations

**Webhooks** — signed JSON POST, HMAC-SHA256 over the exact body:

```bash
arnauth webhook add http://127.0.0.1:9000/hook --event message.received
#   X-Arnauth-Signature: <hex hmac>
#   {"event":"message.received","payload":{...},"protocol":"arnauth.webhook.v1"}
```

Only `http://` with an explicit port. There is no TLS stack in this crate and
saying so beats failing mysteriously. A dead endpoint is logged and swallowed —
it never stops a message from being read.

**Plugins** — a command plus events. The event JSON goes to stdin:

```bash
arnauth plugin add notifier --command /usr/bin/say --arg "new message" \
  --event message.received
```

**A plugin runs as you.** Installing one is equivalent to running it. Nothing
installs a plugin except a human typing `plugin add`.

**MCP for agents** — `arnauth mcp`, six tools: `arnauth_whoami`,
`arnauth_identities`, `arnauth_peers`, `arnauth_send`, `arnauth_inbox`,
`arnauth_receipt`.

```jsonc
{"mcpServers":{"arnauth":{"command":"arnauth","args":["mcp"]}}}
```

It is already wired into this machine's Crush config as `arnauth`, next to
`ultra-mcp` (smart-tree) and `memnet`.

## Where your data lives

```text
~/.arnauth/                        ($ARNAUTH_HOME relocates all of it)
├── active                         the identity you open by default
├── identities/<label>/
│   ├── identity.json              sealed row
│   ├── key.bin                    32-byte seed, 0600  ← this IS the identity
│   ├── pq.bin                     PQ secret halves, 0600
│   └── pq.json                    PQ public halves (for your card)
├── beehive.json                   peers, weights, cells (0600: holds cell keys)
├── contacts.json                  address book
├── webhooks.json                  endpoints + secrets (0600)
├── plugins.json                   plugin commands
├── transport/<dh-pub>.jsonl       the local spool
└── downloads/                     files you received
```

Lose `key.bin`, lose the identity. There is no recovery, no escrow, no support
desk that can help. That is the trade.

## Status

| Feature | State |
|---|---|
| DMs, groups, files, relay | working |
| Hybrid post-quantum | working, negotiated |
| Webhooks, plugins, MCP | working |
| Broadcast channels | working |
| First-run guide, themed GUI | working |
| Voice/video | not yet |
| Multi-device | not yet (one store = one device) |
| On-chain anything | designed, not built — see `docs/web3-design.md` |

```bash
cargo test --workspace        # 133 tests, offline
cargo clippy --workspace --all-targets
cargo fmt --all --check
```

- `SPEC.md` — the binding requirements, each with its acceptance tests
- `TICKETS.md` — what shipped against them, and the known rough edges
- `docs/web3-design.md` — interface, chain architecture, monetization
- `brand/index.html` — landing page
- `brand/ui-mock.html` — interface mock
- `docs/monetization-oss.md` — verified OSS inventory for Ethereum monetization
  (stars, licences, last-push dates checked on the day)

AGPL-3.0-only, matching `wupz-core`, which this crate links.
