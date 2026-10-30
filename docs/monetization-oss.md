# Ethereum monetization — verified open-source inventory

Every row below was checked with `gh repo view` / `gh search repos` on
**2026-10-30**. Stars and last-push dates are as returned by the GitHub API that
day, not remembered. If a number here disagrees with GitHub, GitHub is right.

Why this file exists: the earlier design note (`web3-design.md` §3) listed
distribution surfaces as **unverified** because the search API was unavailable.
This is the replacement, scoped to what can actually be built in Rust against
live OSS.

---

## 1. The one that matters most: x402

| Repo | Stars | Licence | Last push | What it is |
|---|---|---|---|---|
| [`x402-foundation/x402`](https://github.com/x402-foundation/x402) | **6,773** | Apache-2.0 | 2026-10-29 | "A payments protocol for the internet. Built on HTTP." |
| [`coinbase/x402`](https://github.com/coinbase/x402) | 176 | Apache-2.0 | 2026-10-27 | Coinbase's x402 surface |
| [`x402-rs/x402-rs`](https://github.com/x402-rs/x402-rs) | 293 | Apache-2.0 | 2026-07-13 | **Rust**: verify, settle, monitor x402 flows |
| [`MetaMask/mcp-x402`](https://github.com/MetaMask/mcp-x402) | 3 | — | — | MCP server that mints x402 headers |
| [`AgentlyHQ/aixyz`](https://github.com/AgentlyHQ/aixyz) | 82 | — | — | "payment-native AI agents" framework |

**Why it is the right primitive for Arnauth specifically.** x402 is HTTP 402 with
a payment challenge: a server answers `402` with terms, the client pays (stablecoin
over a chain), and retries with proof. Arnauth already speaks two HTTP-adjacent
surfaces — webhooks out, MCP tool calls in — and both are exactly the shape x402
meters. It needs no accounts, no billing dashboard, and no card processor: the
payer is a wallet, the payee is a wallet.

Concrete plan that would not require redesigning anything:

1. Wrap the existing `webhooks` endpoint in a 402 gate (`x402-rs` server side).
2. Meter `arnauth mcp` tool calls: `arnauth_send` free, `arnauth_inbox` free,
   anything that costs compute (blob relay storage, bot invocations) is paid.
3. Price in USDC; the wallet is the user's, never ours.

That is a **per-call** business model, which is the only one that fits agents.

## 2. Recurring and shared money

| Repo | Stars | Licence | Last push | Use in Arnauth |
|---|---|---|---|---|
| [`superfluid-org/protocol-monorepo`](https://github.com/superfluid-org/protocol-monorepo) | 904 | — | — | per-second streaming for cell subscriptions |
| [`sablier-labs/evm-monorepo`](https://github.com/sablier-labs/evm-monorepo) | 354 | — | — | Lockup / Flow / Airdrops if you want vesting or payroll-shaped payouts |
| [`0xSplits/splits-contracts`](https://github.com/0xSplits/splits-contracts) | 162 | — | — | split sticker/bot revenue between creator, relay, and protocol |
| [`unlock-protocol/unlock`](https://github.com/unlock-protocol/unlock) | 884 | — | — | membership NFTs as a **subscription** for creator cells |
| [`Hats-Protocol/hats-protocol`](https://github.com/Hats-Protocol/hats-protocol) | 98 | — | — | on-chain roles: bot permissions, cell moderator, relay operator |

Notes that save time:

- **Unlock vs Superfluid.** Unlock is a membership token with expiry — simpler to
  reason about, good for "this cell costs 5 USDC/month". Superfluid is a real
  stream that flows per second — better UX, harder accounting, and it requires
  the user's wallet to stay funded. Start with Unlock; add Superfluid when
  someone complains about renewals.
- **0xSplits is a deployment, not a feature.** It is a set of contracts plus an
  SDK; integrating means deploying a split per revenue source. Worth it only
  once there is revenue to split.

## 3. Stickers and digital goods

| Repo | Stars | Last push | Verdict |
|---|---|---|---|
| [`OpenZeppelin/openzeppelin-contracts`](https://github.com/OpenZeppelin/openzeppelin-contracts) | **27,329** | 2026-10-30 | the ERC-1155 + ERC-2981 implementation to build on |
| [`thirdweb-dev/contracts`](https://github.com/thirdweb-dev/contracts) | 1,086 | 2026-05-25 | batteries-included drop/marketplace contracts |
| [`ourzora/zora-protocol`](https://github.com/ourzora/zora-protocol) | 212 | 2026-08-11 | minting + secondary market with royalties |
| `stvndf/NFT-ERC1155-marketplace` | 11 | — | toy: read it for shape, do not ship it |
| `saibaneer/erc1155-Marketplace` | 3 | — | same |

Honest read: **there is no good turnkey OSS "sticker marketplace"**. The
marketplace-shaped repos on GitHub are tutorial-sized (0–11 stars). The real
choice is either (a) own the contract — OpenZeppelin ERC-1155 + EIP-2981, ~200
lines, full control — or (b) let Zora/Manifold host it and take their fees.

For a messenger, (a) is right: a sticker is a URL plus a hash, and the chain
only needs to record who owns the pack.

## 4. Wallets and accounts

| Repo | Stars | Last push | Why |
|---|---|---|---|
| [`silius-rs/silius`](https://github.com/silius-rs/silius) | 273 | — | ERC-4337 bundler **in Rust** — the missing piece for an Arnauth smart account |
| [`pimlicolabs/permissionless.js`](https://github.com/pimlicolabs/permissionless.js) | 257 | — | TS client for 4337 if a web companion ever exists |
| `shishirhome/ERC-4337`, `mollybeach/ERC-4337-account-abstraction-contracts` | 10 | — | reference reading only |

The reason ERC-4337 matters here was stated in `web3-design.md` §2.3 and has not
changed: Ethereum consensus signatures are secp256k1, so the only way to make an
on-chain account *actually* post-quantum is to put the PQ verifier inside
`validateUserOp` on a smart account. `silius` being Rust means the same language
and the same CI as Arnauth.

## 5. What the search says about distribution

Searched, and did **not** find an OSS "Ethereum app store" worth listing on. The
surfaces that exist are product-owned directories (Farcaster mini apps, Base,
ENS app directory, MetaMask Snaps, DappRadar) and none of them take a pull
request from a messenger repo. That confirms the earlier ranking:

1. signed DMG / App Store first
2. web build → mini-app surface second
3. chain-native marketplace last

## 6. Ranked recommendation for Arnauth

| Rank | Move | Engine | Effort | Why now |
|---|---|---|---|---|
| 1 | **x402-paid MCP tool calls** | `x402-rs` | small: one middleware around `tools/call` | agents are the paying users, per-call is the natural unit |
| 2 | **Sticker packs** | OpenZeppelin 1155 + 2981 | medium: one contract + `Payload::Blob` already carries the art | highest margin, already works offline |
| 3 | **Unlock cell memberships** | Unlock | medium | recurring revenue without building billing |
| 4 | **0xSplits for payouts** | 0xSplits | small once #2/#3 exist | only meaningful with revenue |
| 5 | **4337 account with PQ verifier** | `silius` + own verifier | large | the only honest route to an on-chain PQ claim |
| — | do not: launch a token, sell metadata, gate messages behind a wallet | — | — | contradicts the product |

## 7. What is still unverified

- Take rates, listing requirements, and whether each directory is currently
  accepting submissions. Those are product decisions that change monthly and are
  not in any repo. Verify against live docs before spending money or promising a
  date.
- `x402-rs` was last pushed 2026-07-13, three months behind the protocol repo
  (2026-10-29). Pin the crate and read its changelog before depending on it; if
  it lags too far, the protocol is small enough to speak directly over `reqwest`
  plus `alloy`.
