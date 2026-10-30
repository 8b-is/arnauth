# arnauth v1 — tickets

Tracer-bullet tickets, in the order they were built. Each row states what
shipped and which tests pin it. Nothing here is "in progress": the tree is green
or it is not.

| # | Ticket | Shipped | Pinned by |
|---|---|---|---|
| 1 | Hybrid PQ bundle: serializable ML-DSA-65 + ML-KEM-768 key material | `pq::PqBundle` with length-prefixed secret encoding, public half stored beside it | `pq_bundle_survives_its_secret_encoding`, `a_truncated_pq_secret_is_refused` |
| 2 | Cards advertise a PQ half | `contacts::PqCard` on `ContactCard.pq`, validated at 1952/1184 bytes | `card_without_pq_still_round_trips`, `PqCard::check` via `a_forged_subject_is_refused` path |
| 3 | Envelope v2: hybrid sealing, mode negotiated from the card | `EnvelopeMode`, `seal_with`, `seal_hybrid`, `open_hybrid`, `open_any`; v1 JSON still parses | `hybrid_round_trip`, `classical_still_works`, `old_json_without_mode_still_parses`, `hybrid_is_not_downgraded` |
| 4 | Hybrid authenticity is really both-or-nothing | Ed25519 + ML-DSA-65 over a v2 domain, AAD v2 | `hybrid_rejects_bad_mldsa`, `hybrid_rejects_a_swapped_ed25519_signature`, `a_classical_envelope_cannot_be_relabelled_hybrid` |
| 5 | PQ keys live beside the identity, not inside the sealed row | `pq.bin` (0600) + `pq.json`, generated in `Home::create` | `create_then_load_round_trips` unchanged; SPEC REQ-5 |
| 6 | Media: content-addressed chunking | `media::{split, blob_id_for, chunk_hash, BlobAssembler}` | `split_and_reassemble_in_order`, `reassemble_out_of_order`, `assembled_bytes_match_blob_id` |
| 7 | Media survives the wire | payload tag `0x04` | `blob_payload_round_trips`, `a_truncated_blob_header_is_refused` |
| 8 | Media survives a restart | `media::ChunkStore` staging on disk | `chunk_store_survives_a_missing_chunk`, `chunk_store_ignores_duplicate_indexes`, `chunk_store_refuses_a_corrupt_chunk` |
| 9 | Chunk corruption is contained | hash checked before write; bad chunk leaves no state | `a_corrupt_chunk_is_refused` |
| 10 | Relay: memory-only store-and-forward | `relay::{RelayServer, RelayClient}`, `PUT`/`GET`, drain-on-read | `push_then_pull`, `queues_are_isolated`, `queue_cap_drops_oldest` |
| 11 | Relay survives bad clients | malformed frame closes one connection, nothing else | `malformed_frame_does_not_kill_the_server`, `a_bad_queue_name_is_refused` |
| 12 | CLI speaks files and relays | `send --file`, `send --via`, `inbox --via`, `inbox --save`, `relay serve` | smoke: 200 KB file → 4 chunks → identical sha256; relay round trip |
| 13 | GUI reaches the same capability | attach path in compose, PQ status on identity, blob save into `<home>/downloads` | GUI launches clean against a store holding a PQ peer and a received blob |
| 14 | Spec written before code | `SPEC.md` with REQ-1..5 and named acceptance tests | this file |

## Deliberately not ticketed (out of scope for v1)

wallet, contracts, ENS, payments, voice/video, multi-device, push, group rekey,
web build, mobile, relay auth, relay persistence.

## Known rough edges, named rather than hidden

- `GET` drains, so two devices pulling the same queue race. Fine for v1; a
  multi-device answer needs per-device queues, not a lock.
- Relay has no rate limiting. It is bound to localhost in every documented use.
- A blob's `kind` is guessed from the extension in the CLI and hardcoded
  `application/octet-stream` in the GUI.
- Hybrid envelopes are ~10 KB before the body: 1952 B key + 3309 B signature +
  1088 B ciphertext, all hexed. Correct, not compact.
