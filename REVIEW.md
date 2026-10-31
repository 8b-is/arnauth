# arnauth — review pass

Reviewed `main` at `b3d74ff`. This is a self-review: what holds up, what was
wrong, what is still wrong. Everything claimed below was checked against the
tree on this machine, not remembered.

Verdict in one line: **the crypto and the store are sound; the edges had two
hang bugs and one portability lie, all now fixed.**

---

## 1. Bugs found and fixed in this pass

### 1.1 A plugin could hang the inbox forever

`PLUGIN_TIMEOUT_MS` was declared at `plugin.rs:26`, the doc comment promised
output was "bounded by the timeout", and nothing used it. `run()` called
`wait_with_output()`, which blocks indefinitely.

Because `dispatch()` runs inside the inbox path, one `sleep 1000` plugin hung
`arnauth inbox` and, in the GUI, the whole frame. A documented timeout that does
not exist is worse than no timeout: it is a promise the code does not keep.

Fixed: `run_with_timeout` polls `try_wait` against a deadline, kills, reaps, and
reports `timed out after N ms`. `run` is the same call with the default.

Pinned by `a_hanging_plugin_is_killed_at_the_deadline` (asserts the call returns
in under 5 s for a `sleep 30` plugin with a 150 ms budget).

### 1.2 A chatty plugin could deadlock on a full pipe

With pipes and no reader, a child that writes more than the pipe buffer (~64 KiB)
blocks on `write`, the parent blocks on `wait`, and neither moves. That is the
classic wait-then-read deadlock, and it is *introduced* by fixing 1.1 naively
(poll-for-exit without draining).

Fixed: stdout and stderr are drained on their own threads, then joined after
exit. `a_chatty_plugin_does_not_deadlock_on_a_full_pipe` pushes 256 KiB through
and asserts it arrives clipped.

### 1.3 Clipping could panic on a multi-byte character

`clip()` did `&text[..2000]`. A plugin emitting 2000 bytes of ASCII then a kanji
would panic on a non-char-boundary slice — a plugin could crash the inbox by
printing the wrong thing.

Fixed: walk back to the nearest `is_char_boundary`. Pinned by
`clipping_never_splits_a_character`.

### 1.4 Webhooks could stall for the kernel's SYN timeout

`TcpStream::connect` has no application deadline. A receiver whose host
blackholes packets leaves the connect hanging for tens of seconds, inside the
inbox path, once per hook.

Fixed: `connect_timeout(3 s)` after `to_socket_addrs`, plus 5 s read/write
timeouts on the socket. Pinned by `an_unresolvable_endpoint_fails_fast`.

### 1.5 The multi-OS claim was false for plugins

README says macOS, Linux, and Windows. Every other module is portable, but
`plugin::run` hardcoded `/bin/sh`, so plugins were unix-only and would fail
`<could not start: No such file or directory>` on Windows.

Fixed: `shell_command()` picks `cmd /C` on Windows and `/bin/sh -c` elsewhere.
The quoting helper stays unix-only and is only reached on unix.

### 1.6 `command` vs shell line was ambiguous

`Plugin.command` is the program; `args` are its arguments. Nothing said so, and
`plugin("hang", "sleep 30")` silently failed with `command not found` because the
quoted string became one program name. The behaviour is right (no surprise shell
interpretation), so it is now documented *and* pinned:
`the_command_is_a_program_not_a_shell_line`.

---

## 2. What holds up

Checked, not assumed:

| Area | Evidence |
|---|---|
| Hybrid envelopes | both halves verified, downgrade refused, v1 JSON still parses |
| Identity seal | hand-edited rows rejected (`a_hand_edited_row_is_rejected`) |
| Store permissions | `0600` asserted on `key.bin` and `webhooks.json` |
| File transfer | 150 KB random file round-tripped, sha256 identical |
| Chunk resume | `ChunkStore` survives a missing chunk and ignores duplicates |
| Relay | push/pull, per-queue isolation, drain-on-read, bad client survivable |
| MCP | 8 tests plus a live 5-request pipe |
| Plugins | real `/bin/cat` receives the event; shell quoting holds |

`cargo test --workspace` = **147 tests** (139 in `arnauth-core`, 8 in `arnauth-cli`), `clippy --all-targets` zero warnings,
`fmt --check` clean.

---

## 3. Still wrong, ranked

1. **The relay has no authentication and no rate limit.** Documented as
   localhost-only, but nothing enforces that: `relay serve --bind 0.0.0.0:8795`
   will happily accept the internet. One bad actor can fill the process memory
   up to `cap × MAX_FRAME` per queue. *Next slice: bind to loopback unless
   `--allow-remote` is passed.*
2. **`GET` drains, so two devices pulling the same queue race.** Named in
   TICKETS; the fix is per-device queues, not a lock.
3. **Group membership never rekeys.** A removed member keeps the key for
   everything already sent, and the cell is not rekeyed on leave. Honest in the
   README, still the biggest real-world gap.
4. **No disk cap on staged blobs.** `ChunkStore` will happily stage until the
   filesystem fills. Needs a per-store budget and a sweeper for abandoned blobs.
5. **MCP `arnauth_inbox` does not decrypt group messages or save blobs** — it
   reports them. Deliberate (the agent should not silently claim a file), but the
   agent cannot do it either, so a group-only workflow stalls at the tool layer.
6. **No relay or webhook tests on Windows.** The `cfg(windows)` branch compiles
   nowhere in CI because there is no CI.

---

## 4. Honest note on the outreach deck

The LinkedIn material cites *"hybrid PQ capability envelopes (142/142 tests)"*.
At the time that was written the suite was **133**, and it is **147** now
(139 core + 8 CLI). The
number was neither derived nor checked. Re-derive it from `cargo test` before any
deck ships; a test count in a sales document is a fact claim like any other.

---

## 5. Suggested next three slices

1. **Loopback-by-default relay** + `--allow-remote` + a per-queue byte budget
   (small, closes the only remotely-exploitable surface).
2. **Cell rekeying**: new key per epoch, wrapped to the remaining members, old
   keys retired. This is what "groups" means in practice.
3. **Blob budget + sweeper**, so a stranger cannot fill your disk with half-sent
   files.
