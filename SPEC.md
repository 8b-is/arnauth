# arnauth v1 — specification

Status: **binding for v1**. Every requirement below has an acceptance test named
in this document; a requirement without a passing test is not met.

Supersedes nothing. Companion to `docs/web3-design.md` (which is the *why*).

---

## 0. Scope

**v1 is a messenger you can hand to two people.** It is not a web3 product.

### In scope

| # | Capability |
|---|---|
| REQ-1 | Hybrid post-quantum envelopes, negotiated per peer |
| REQ-2 | Media: chunked, resumable, content-addressed blobs |
| REQ-3 | Relay: one dumb store-and-forward node, no metadata |
| REQ-4 | CLI and GUI both speak every capability above |
| REQ-5 | Any v1 store from before this spec keeps opening |
| REQ-6 | Webhooks: signed JSON POST per event, never blocking message handling |
| REQ-7 | MCP over stdio, so an agent can drive the store |
| REQ-8 | A first run that explains itself: `arnauth quickstart` and a GUI guide |

### Out of scope (named so nobody assumes them)

wallet, contracts, ENS, payments, voice/video, multi-device sync, push
notifications, group rekey, web build, mobile.

---

## 1. REQ-1 — hybrid envelopes

### 1.1 Behaviour

1. A contact card **may** carry a post-quantum half:
   `pq: { mldsa_vk: <hex, 1952 B>, mlkem_ek: <hex, 1184 B> }`, omitted for
   classical-only peers.
2. `Envelope` gains `mode: "classical" | "hybrid"` (serde default `classical`)
   and, when hybrid, `mldsa_vk`, `mldsa_signature`, `mlkem_ct`.
3. Sending to a card **with** `pq` produces `mode: hybrid`; otherwise classical.
4. Opening:
   - `classical` → verify Ed25519, X25519 DH (unchanged v1 path).
   - `hybrid` → verify **both** Ed25519 and ML-DSA-65; establish with
     X25519 **and** ML-KEM-768, HKDF over both.
5. A hybrid envelope received by a peer whose card has no PQ keys is **rejected
   with a pointed error**, never silently downgraded to classical.

### 1.2 Acceptance

| Test | Asserts |
|---|---|
| `envelope::tests::hybrid_round_trip` | hybrid seal → open returns the body |
| `envelope::tests::classical_still_works` | v1 path untouched |
| `envelope::tests::hybrid_rejects_bad_mldsa` | flipping one ML-DSA byte fails |
| `envelope::tests::hybrid_is_not_downgraded` | recipient without PQ keys refuses |
| `envelope::tests::old_json_without_mode_still_parses` | `mode` defaults to classical |
| `contacts::tests::card_without_pq_still_round_trips` | cards stay backwards compatible |

---

## 2. REQ-2 — media

### 2.1 Behaviour

1. `media::split(bytes, chunk_max)` produces `BlobChunk { blob_id, index, total,
   name, kind, data, chunk_hash }`.
2. `blob_id = sha256("arnauth.blob.v1\0" || total_len_le || content)`.
   `chunk_hash = sha256(data)`.
3. Payload tag `0x04` carries a chunk.
4. `BlobAssembler::accept` stores chunks out of order, deduplicates repeats,
   verifies each chunk hash on arrival, and only completes when `total` chunks
   are present **and** the assembled content hashes to `blob_id`.
5. A corrupted chunk is rejected and does not poison the assembler.
6. Chunks survive JSON, hexing, and the spool unchanged.

### 2.2 Acceptance

| Test | Asserts |
|---|---|
| `media::tests::split_and_reassemble_in_order` | round trip, hash matches |
| `media::tests::reassemble_out_of_order` | chunk 2 before chunk 0 |
| `media::tests::duplicate_chunks_are_idempotent` | repeat delivery is harmless |
| `media::tests::a_corrupt_chunk_is_refused` | hash mismatch → error, state clean |
| `media::tests::incomplete_blob_never_completes` | 2 of 3 chunks → `None` |
| `media::tests::assembled_bytes_match_blob_id` | final hash is checked |
| `payload::tests::blob_payload_round_trips` | tag 0x04 encode/decode |

---

## 3. REQ-3 — relay

### 3.1 Behaviour

1. `RelayServer::bind(addr)` serves a line protocol over TCP:

   ```
   PUT <queue-hex> <len>\n<len bytes of JSON envelope>\n  → OK\n
   GET <queue-hex>\n                                     → OK <n>\n<n lines>\n
   ```

   `GET` **drains** the queue. A courier that re-serves every delivery on every
   poll is a courier that never stops talking.

   `queue-hex` is `hex(to_dh_public)`, the same key the local spool uses.
2. The server **writes nothing to disk and logs nothing**. It holds queues in
   memory only, capped per queue, and drops the oldest first.
3. `RelayClient::push(queue, envelope)` and `::pull(queue)` are the only client
   surface. No retries beyond the caller's loop, no auth in v1 — the transport
   is a courier, envelopes are already sealed.
4. A malformed frame closes the connection without crashing the server: one bad
   client must not take down the node.

### 3.2 Acceptance

| Test | Asserts |
|---|---|
| `relay::tests::push_then_pull` | envelope survives the socket |
| `relay::tests::queues_are_isolated` | one queue cannot read another |
| `relay::tests::malformed_frame_does_not_kill_the_server` | bad frame, then a good one still works |
| `relay::tests::queue_cap_drops_oldest` | bounded memory is real |

---

## 4. REQ-4 — surfaces

- CLI: `send --file <path>`, `inbox --save <dir>`, `relay serve --bind`,
  `send --via <addr>`, `inbox --via <addr>`.
- GUI: PQ mode shown on the identity and thread; attach a file by path; save a
  completed blob to a directory.
- No capability exists in the CLI that the GUI cannot reach, and vice versa.

### Acceptance

Smoke script in `AGENTS.md`; both binaries build and the GUI launches without a
panic against a store containing a PQ peer and a received blob.

---

## 4a. REQ-6 — webhooks

### Behaviour

1. `Webhooks` lives at `<home>/webhooks.json`, mode 0600 (it holds secrets).
2. `add(url, events)` accepts only `http://` with an explicit port. `https://` is
   refused **with the reason** (no TLS stack in this crate), never a vague
   failure.
3. Every delivery is `POST` with `Content-Type: application/json` and
   `X-Arnauth-Signature: hex(hmac_sha256(secret, body))` over the exact bytes.
4. Delivery failure is logged and swallowed: a dead endpoint must not stop a
   message from being read.
5. Events: `message.received {from, channel, bytes}`,
   `blob.completed {name, kind, bytes, path}`, `webhook.test`.

### Acceptance

`api::tests::{a_hook_receives_a_signed_post, a_dead_endpoint_is_a_logged_failure_not_a_panic,
event_filtering_is_exact, https_is_refused_with_an_explanation, hooks_are_world_unreadable}`,
plus an independent verifier: a Python receiver recomputed the HMAC and agreed.

## 4b. REQ-7 — MCP

### Behaviour

1. `arnauth mcp` speaks newline-delimited JSON-RPC 2.0 on stdio.
2. Methods: `initialize`, `ping`, `tools/list`, `tools/call`.
3. Tools: `arnauth_whoami`, `arnauth_identities`, `arnauth_peers`,
   `arnauth_send`, `arnauth_inbox`, `arnauth_receipt`.
4. A tool failure is an MCP tool result with `isError: true` and a readable
   message — never a process exit.
5. Diagnostics go to stderr so the protocol stream stays clean.

### Acceptance

`mcp::tests::{initialize_advertises_tools, tools_list_names_every_tool_from_the_catalog,
whoami_works_once_an_identity_exists, send_then_inbox_round_trips_through_mcp,
an_unknown_tool_is_reported_as_an_error, an_unknown_method_is_a_jsonrpc_error}`,
plus a live run: five requests piped into the binary, five valid responses.

## 4c. REQ-8 — first run

`arnauth quickstart [label]` mints or reuses an identity, writes
`<home>/my-card.json`, reports seal and PQ status, and prints numbered next
steps that only include what is actually missing. The GUI opens on a four-step
guide when the store is empty, and every step folds away once done.

## 5. REQ-5 — compatibility

1. A store written before this spec (no `mode`, no `pq`) loads and opens.
2. `identity.json` rows are untouched: the seal covers the same bytes.
3. No existing test is deleted to make a new one pass.

### Acceptance

Full pre-existing suite stays green; `cargo test --workspace` count only grows.

---

## 6. Definition of done

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets   # zero warnings
cargo test --workspace                   # all green
```

plus: every REQ has its named tests, `README.md` updated, `TICKETS.md` reflects
what actually shipped, and the tree is committed.

---

## 7. Wire formats

### 7.1 Envelope (v1-compatible superset)

```json
{
  "protocol": 1,
  "mode": "classical | hybrid",
  "from_label": "alice.eth",
  "from_verifying_key": "<hex 32>",
  "from_dh_public": "<hex 32>",
  "to_dh_public": "<hex 32>",
  "ephemeral_public": "<hex 32>",
  "mlkem_ct": "<hex 1088>",          // hybrid only
  "mldsa_vk": "<hex 1952>",          // hybrid only
  "nonce": "<hex 12>",
  "ciphertext": "<hex>",
  "signature": "<hex 64>",           // Ed25519, always
  "mldsa_signature": "<hex 3309>",   // hybrid only
  "created_ms": 1793344397462
}
```

### 7.2 Payload tags

| Tag | Meaning |
|---|---|
| `0x01` | text |
| `0x02` | group key handoff |
| `0x03` | group message |
| `0x04` | blob chunk |

### 7.3 AAD / signature domains

`hybrid` binds `mode || from_ed || from_vk?` — concretely, the hybrid signature
input is `b"arnauth.envelope.v2\0" || header || len(ct) || ct`, and the AEAD AAD
is `b"arnauth.envelope.aad.v2\0" || header`. Domain separation is the whole
reason a v2 signature can never be replayed as a v1 one.
