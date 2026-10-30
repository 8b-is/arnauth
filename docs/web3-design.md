# Arnauth — web3 design note

Status: **design + working crypto, no chain code yet.** Written 2026-10-30.

What is real today in this repo: sealed identities, hybrid-capable post-quantum
primitives (`crates/arnauth-core/src/pq.rs`, 8 tests), sender-key groups, and the
beehive. What is not: any contract, any wallet, any ENS call, any payment.

The point of this document is to be honest about which parts are engineering and
which parts are a plan.

---

## 1. The interface

### 1.1 Shape

Three panes, one command surface.

```
┌──────────────┬───────────────────────────────────┬────────────────┐
│ rail         │ thread                            │ inspector      │
│              │                                   │                │
│ ⬤ saturn.ring│  alice.eth            14:02       │ identity       │
│   4 members  │  ┌──────────────────────┐         │  seal  ✓ wupz  │
│              │  │ one body, one key    │         │  sig   ✓ ed25519│
│ ⬤ kai.eth    │  │ for the whole cell   │         │  pq    ✓ ml-dsa│
│   attested   │  └──────────────────────┘         │  claimed? no   │
│              │   ✓ hybrid · 0xa62…               │                │
│ ○ nova.eth   │                                   │ wallet         │
│   claimed    │  you@mail.com        14:03        │  1,240 FOKEN   │
│              │  ┌──────────────────────┐         │  ─ zeno        │
│ ── bots ──   │  │ …                    │         │                │
│ ⚙ kintsugi   │  └──────────────────────┘         │                │
└──────────────┴───────────────────────────────────┴────────────────┘
                    ⌘K  everything
```

Principles, each with a reason:

- **⌘K is the primary navigation.** A chat app grows a directory problem the
  moment you have 40 cells. Command palette beats a sidebar tree for j/k-style
  keyboard users, and it is the one surface where search, creation, and
  navigation collapse into one field.
- **Warmth, not presence.** Do not fake "online" dots — this app has no server
  that knows. The rail orders by beehive weight, so someone you actually talk to
  drifts up and someone you stopped talking to drifts down and eventually
  disappears. The interface tells the truth about forgetting.
- **The trust ladder is visible.** Every conversation shows four independent
  facts, never one aggregate "verified" badge:

  | Rung | Means | Where it comes from |
  |---|---|---|
  | `claimed` | a label off the wire; key proven, name not | `Beehive::learn_claimed` |
  | `attested` | a card you imported out of band | `arnauth trust` |
  | `sealed` | identity row passes its wupz frame | `Identity::verify` |
  | `hybrid` | both Ed25519 *and* ML-DSA signatures verified | `pq::hybrid_verify` |

  Green ticks are cheap to lie with. Four separate rungs, each with its own
  failure mode, are not.
- **One action per screen.** Compose is compose. No composer in the rail, no
  inline send next to a settings field.
- **Motion is a signal, not decoration.** View transitions on pane and palette
  changes, never on message arrival (a message that slides is a message you
  miss). `prefers-reduced-motion: reduce` removes all of it.

### 1.2 Tokens

The mock in `brand/ui-mock.html` uses the `ultralovegod` palette from
`design.vaked.dev/palettes/8b-is-palettes.json`:

| Token | Hex | Use |
|---|---|---|
| `--bg` | `#0B0914` | void |
| `--c1` | `#FF6AC1` | primary action, active cell |
| `--c3` | `#00E5C9` | structural / secondary |
| `--c2` | `#FFD700` | hold, caution, `claimed` |
| `--c6` | `#00FF66` | witness, `attested`/`sealed` |
| prune | `#FF3366` | rejected, mismatch |

Ternary polarity is used literally: `+1` green is "witnessed", `0` gold is
"deliberative pause" (claimed, unconfirmed), `-1` red is "pruned" (seal
mismatch, bad signature).

### 1.3 Accessibility and modern CSS

- Container style queries for density (`compact`, `comfortable`, `blueprint`),
  not viewport widths.
- `:focus-visible` rings on the palette input and every selectable, contrast
  ≥ 4.5:1 against `--bg`.
- `document.startViewTransition()` wrapped with a reduced-motion guard.
- No web fonts; system stack. A messenger that blocks on a font request is a
  messenger that fails offline.

---

## 2. Web3 layer

### 2.1 What goes on chain, and what must not

| Concern | On chain? | Why |
|---|---|---|
| Message bodies | **never** | cost, and permanence is the opposite of a chat app's privacy model |
| Cell membership | optional: Merkle root per epoch | auditable membership without publishing the list |
| Public keys | `ArnauthRegistry` | discovery only; envelopes remain self-authenticating |
| Labels / ENS | optional pointer | display and addressability, never the source of truth |
| Payments | yes | settlement is what a chain is for |
| Stickers / packs | yes, ERC-1155 | ownership and secondary market need a ledger |

The rule: **the chain is a directory and a till, not a transport.** An envelope
that needs a chain read to open is an envelope that breaks when the RPC does.

### 2.2 Contracts

```solidity
// sketch, not deployed
interface IArnauthRegistry {
    struct Keys {
        bytes32 subject;      // sha256("arnauth.subject.v1" || label)
        bytes32 ed25519;      // 32 bytes
        bytes32 x25519;       // 32 bytes
        bytes  mldsaVk;       // 1952 bytes (FIPS 204, ML-DSA-65)
        bytes  mlkemEk;       // 1184 bytes (FIPS 203, ML-KEM-768)
        uint32 version;       // key rotation epoch
    }
    function publish(Keys calldata k) external;
    function keys(bytes32 subject) external view returns (Keys memory);
}

interface IStickerPack {          // ERC-1155
    function mint(uint256 packId, uint256 amount) external payable;
    function royaltyInfo(uint256 packId, uint256 salePrice)
        external view returns (address, uint256);   // EIP-2981
}

interface ICellManifest {         // optional, per epoch
    function commit(bytes32 cellId, bytes32 memberRoot, uint64 epoch) external;
}
```

`IArnauthRegistry` publishes **both** classical and post-quantum public keys.
That is the whole reason to have a registry in a hybrid world: a peer needs four
public keys to reach you, and typing four hex blobs is not a user experience.

### 2.3 "Quantum-proof" — what it does and does not mean

This is where most web3 projects overclaim, so be precise.

**What we have.** `pq.rs` implements hybrid X25519 + ML-KEM-768 key
establishment and hybrid Ed25519 + ML-DSA-65 signatures, both FIPS-final
parameters. Verified by test:

```
ml_kem_round_trips                     ok
ml_kem_ciphertext_size_is_fips_203      ok   (1088-byte ct, 1184-byte ek)
pq_signature_sizes_are_fips_204         ok   (1952-byte vk, 3309-byte sig)
hybrid_kem_agrees_across_sides          ok
hybrid_signatures_need_both_halves      ok
the_combined_key_is_not_on_the_wire     ok
```

**What we do not have.** Ethereum consensus signatures are secp256k1. No amount
of Rust in this repo changes that. Concretely:

- A transaction signature today is **not** post-quantum safe. Anything an address
  signs is exposed to a future quantum adversary who recorded the chain.
- Therefore: **quantum safety lives off-chain**, in message envelopes, until
  either a PQ precompile ships or you put the PQ verifier inside an
  ERC-4337 smart account's `validateUserOp` (the verifier contract cost is the
  blocker; ML-DSA verification is heavy for the EVM).

So the honest product claim is: *"Messages and identities are hybrid
post-quantum. On-chain settlement is as quantum-safe as Ethereum is, which today
is not."* Do not put "quantumproof" on the marketing page without that sentence
next to it.

**Migration path.** `Envelope` stays v1 (classical) until `envelope.v2` lands
with `{ ed25519, mldsa, x25519_eph, mlkem_ct }`. v1 conversations must keep
opening, so v2 is a negotiated capability in the contact card, not a flag day.
`pq.rs` sits unwired on purpose until that slice exists.

### 2.4 VAKED / FOKEN

From `zeno.vaked.dev` (read locally, verified):

- `VAKED Coin (FOKEN)` is one unit — `zeno_cli.py:198` prints
  `VAKED COIN (FOKEN) -> USD`.
- `zeno-engine.js:314` settles at `100 JPY per FOKEN`.
- `zeno-engine.js:258` has the `FokenGateValidator`: FOKEN is
  **proof-of-contribution**, a *gate*, not a tips jar.

That last point is the interesting design constraint. FOKEN is not for buying
stickers; it is for proving you contributed and therefore may pass a gate. So:

| Feature | Currency | Gate |
|---|---|---|
| Sticker packs (own + resell) | ETH / USDC on chain | none |
| Bot installs | ETH on chain | FOKEN contribution ≥ threshold |
| Cell creation beyond N | — | FOKEN contribution |
| Relay priority (when a relay exists) | ETH | FOKEN contribution |
| Tips between peers | zeno ledger, off chain | none |

This keeps zeno's household accounting and the chain's settlement separate, which
is the only way the two coexist without double-entry lying to itself.

---

## 3. Monetization

**Verification status: unverified.** My web-search tool ran out of credits
during this session, so everything below is from prior knowledge and must be
checked against live docs before anyone spends money or integrates. I am not
going to invent take rates or "we are live on X".

### 3.1 Distribution surfaces (all need verification)

| Surface | What it would take | Note |
|---|---|---|
| Farcaster mini apps / frames | a web build + manifest; the app is desktop-native today, so this means a web target first | candidate |
| Base ecosystem app listings | a deployed app + on-chain activity | candidate |
| ENS app directory | ENS integration that is real, not cosmetic | candidate |
| MetaMask Snaps / dapp directory | a browser-addressable build | candidate |
| Coinbase Wallet dapp browser | same | candidate |
| DappRadar / Dune dashboards | analytics plus a listing request | discovery, not revenue |
| Zora / Paragraph | for the writing and the sticker packs, not the messenger | tangential |
| Steam/App Store/Play | desktop app distribution, not web3 | the boring, high-conversion path |

Honest ranking for this product: **App Store and a signed notarised DMG first**,
web3 surfaces second. A desktop messenger that only exists inside a wallet
browser has no users at 09:00 on a Tuesday.

### 3.2 Revenue features, in the order they pay

1. **Custom stickers as ERC-1155 packs.** Packs mint on chain, work off chain
   (a sticker is a URL plus a hash), 5–10% secondary royalty via EIP-2981. This
   is the highest-margin, lowest-risk web3 feature a chat app can ship.
2. **Bot manifests.** A directory of bots with a manifest hash, an install
   counter, and a revenue split. Discord and Telegram both proved the model;
   on-chain settlement adds portable reputation, which is the only part that
   genuinely needs a chain.
3. **Cell subscriptions.** Creator cells charge in ETH/USDC; settlement on chain,
   access enforced by a token check written into the cell's manifest.
4. **Premium identity.** Paid ENS subnames (`you.arnauth.eth`), vanity subjects,
   custom seal art. Cheap to run, pure margin, and it makes the trust ladder
   visible in a way people screenshot.
5. **Relay priority.** Only after a relay exists. Do not sell capacity you have
   not built.

### 3.3 What to refuse

- Selling message metadata, ever. It contradicts the entire security story.
- Token-gating *messages* (as opposed to cells). A messenger that can lock a
  conversation behind a wallet is a messenger that will.
- A launch token for the app itself. FOKEN already exists as a contribution
  gate; a second token would be a meme, not a product.

---

## 4. Build order

| # | Slice | Why now |
|---|---|---|
| 1 | `envelope.v2` with hybrid signatures, capability-negotiated | `pq.rs` is ready and unwired |
| 2 | media: chunked blobs, hash-addressed, resumable | users judge a messenger on images |
| 3 | relay: one dumb store-and-forward node, no metadata | the spool stops being a manual copy |
| 4 | `ArnauthRegistry` + ENS subname issuance | discovery, and the first money |
| 5 | ERC-1155 sticker packs | first revenue |
| 6 | ERC-4337 account with a PQ verifier | the only honest path to on-chain PQ claims |
| 7 | bot manifests and the directory | marketplace, after there are users |

Slices 1–3 are the product. 4–6 are the business. Shipping 4 before 2 is the
classic web3 mistake and this note exists to name it.

---

## 5. Threat model

| Threat | Mitigation | Residual |
|---|---|---|
| Forged sender label | hybrid signature; label is `claimed` until attested | name binding is out of band |
| Stolen device | seed is `0600`, one identity per file; no escrow | a stolen unlocked device is a stolen identity |
| Recorded traffic, future quantum | hybrid KEM/SIG off chain | on-chain tx signatures remain secp256k1 |
| Malicious group member | sender-key cells; removal stops future reads | no rekey yet, past messages stay readable |
| Hand-edited store | wupz seal per identity row | an attacker who rewrites row *and* seal wins |
| Spool tampering | envelope signature + AEAD | denial of service is unchecked |
| Registry poisoning | envelopes never trust the registry for keys, only for discovery | a first-contact MITM needs an out-of-band card |
