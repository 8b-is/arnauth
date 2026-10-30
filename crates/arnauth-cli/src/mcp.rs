//! MCP over stdio: the agent-facing API.
//!
//! Crush, Claude Code, and anything else that speaks MCP can drive Arnauth with
//! this. It is the whole integration surface for agents — no HTTP, no tokens,
//! no daemon: the tool process *is* the credential, because it runs as you and
//! opens your store.
//!
//! Protocol: newline-delimited JSON-RPC 2.0 on stdin/stdout, as MCP specifies
//! for stdio transport. Diagnostics go to stderr so they never corrupt the
//! stream.

use std::io::{BufRead, Write};

use arnauth_core::api::{Event, Webhooks};
use arnauth_core::beehive::Beehive;
use arnauth_core::envelope::Envelope;
use arnauth_core::identity::now_ms;
use arnauth_core::payload::Payload;
use arnauth_core::store::Home;
use arnauth_core::transport::Spool;
use arnauth_core::Result;
use serde_json::{json, Value};

/// MCP revision this server implements.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// Serve until stdin closes.
pub fn serve(home: Home) -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(e) => {
                let error = error_response(Value::Null, -32700, &format!("parse error: {e}"));
                let _ = writeln!(stdout, "{error}");
                let _ = stdout.flush();
                continue;
            }
        };

        // Notifications carry no id and get no response.
        if request.get("id").is_none() {
            continue;
        }

        let response = handle(&home, &request);
        let _ = writeln!(stdout, "{response}");
        let _ = stdout.flush();
    }

    Ok(())
}

/// Handle one request. Pure enough to unit-test with a store on disk.
pub fn handle(home: &Home, request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or_default();

    match method {
        "initialize" => ok(id, initialize_result()),
        "ping" => ok(id, json!({})),
        "tools/list" => ok(id, json!({ "tools": tool_catalog() })),
        "tools/call" => {
            let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
            match call_tool(home, &params) {
                Ok(text) => ok(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": text }],
                        "isError": false
                    }),
                ),
                Err(e) => ok(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": format!("{e}") }],
                        "isError": true
                    }),
                ),
            }
        }
        other => error_response(id, -32601, &format!("unknown method {other:?}")),
    }
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": "arnauth", "version": env!("CARGO_PKG_VERSION") },
        "instructions": "Arnauth: talk as an email you already own, or a name you mint. \
    Messages are sealed end-to-end with hybrid post-quantum cryptography. \
    Use arnauth_whoami first, then arnauth_send / arnauth_inbox. \
    Nothing here needs a phone number."
    })
}

fn tool_catalog() -> Vec<Value> {
    vec![
        json!({
            "name": "arnauth_whoami",
            "description": "The active identity: label, subject, whether its seal verifies, and whether it holds post-quantum keys.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "arnauth_identities",
            "description": "List every identity in the local store with its seal status.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "arnauth_peers",
            "description": "The beehive: known peers with weight and whether their name is attested or merely claimed.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "arnauth_send",
            "description": "Seal a text message to a peer. Requires the peer to be in the address book or the local store.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "to": { "type": "string", "description": "Recipient label, e.g. kai.eth or you@mail.com" },
                    "body": { "type": "string", "description": "Message text" }
                },
                "required": ["to", "body"]
            }
        }),
        json!({
            "name": "arnauth_inbox",
            "description": "Read sealed messages waiting for the active identity. Set take=true to remove them after reading.",
            "inputSchema": {
                "type": "object",
                "properties": { "take": { "type": "boolean" } }
            }
        }),
        json!({
            "name": "arnauth_receipt",
            "description": "Seal the whole local communication graph into one 64-byte frame, so two machines can compare state in one check.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
    ]
}

fn call_tool(home: &Home, params: &Value) -> Result<String> {
    let name = params
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or_default();
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    match name {
        "arnauth_whoami" => {
            let (identity, _) = home.active()?;
            let pq = home.pq(&identity.label)?.is_some();
            Ok(format!(
                "label: {}\nkind: {}\nsubject: {}\nseal verified: {}\npost-quantum keys: {}\nstore: {}",
                identity.label,
                identity.kind,
                hex::encode(identity.subject),
                identity.verify(),
                if pq { "yes (ml-dsa-65 + ml-kem-768)" } else { "no" },
                home.identity_dir(&identity.label).display()
            ))
        }

        "arnauth_identities" => {
            let mut out = String::new();
            let active = home.active_label()?;
            for identity in home.summary()? {
                let mark = if Some(&identity.label) == active.as_ref() {
                    "*"
                } else {
                    " "
                };
                out.push_str(&format!(
                    "{mark} {:<32} seal={}\n",
                    identity.label,
                    if identity.verify() { "ok" } else { "MISMATCH" }
                ));
            }
            if out.is_empty() {
                out.push_str("no identities yet\n");
            }
            Ok(out)
        }

        "arnauth_peers" => {
            let hive = Beehive::load(home)?;
            if hive.peers.is_empty() {
                return Ok("the hive is empty\n".into());
            }
            let mut peers: Vec<_> = hive.peers.iter().collect();
            peers.sort_by_key(|peer| std::cmp::Reverse(peer.weight));
            let mut out = String::new();
            for peer in peers {
                out.push_str(&format!(
                    "{:<32} w={:<4} {}\n",
                    peer.card.label,
                    peer.weight,
                    if peer.claimed { "claimed" } else { "attested" }
                ));
            }
            Ok(out)
        }

        "arnauth_send" => {
            let to = args.get("to").and_then(|v| v.as_str()).ok_or_else(|| {
                arnauth_core::Error::Malformed {
                    what: "arnauth_send",
                    detail: "missing `to`".into(),
                }
            })?;
            let body = args.get("body").and_then(|v| v.as_str()).ok_or_else(|| {
                arnauth_core::Error::Malformed {
                    what: "arnauth_send",
                    detail: "missing `body`".into(),
                }
            })?;

            let (identity, keys) = home.active()?;
            let our_pq = home.pq(&identity.label)?;
            let recipient = home.resolve_card(to)?;
            let payload = Payload::Text(body.as_bytes().to_vec()).encode();
            let envelope =
                Envelope::seal_with(&identity, &keys, our_pq.as_ref(), &recipient, &payload)?;
            Spool::new(home).deliver(recipient.dh_public, &envelope)?;

            let mut hive = Beehive::load(home)?;
            hive.learn(recipient.clone(), now_ms())?;
            hive.touch(&recipient.subject, true, now_ms());
            hive.save(home)?;

            let mode = match envelope.mode {
                arnauth_core::envelope::EnvelopeMode::Hybrid => "hybrid",
                arnauth_core::envelope::EnvelopeMode::Classical => "classical",
            };
            Ok(format!(
                "sealed for {} ({mode}, {} bytes)\n",
                recipient.label,
                envelope.ciphertext.len()
            ))
        }

        "arnauth_inbox" => {
            let take = args.get("take").and_then(|v| v.as_bool()).unwrap_or(false);
            let (identity, keys) = home.active()?;
            let our_pq = home.pq(&identity.label)?;
            let spool = Spool::new(home);
            let envelopes = if take {
                spool.take(identity.dh_public)?
            } else {
                spool.pending(identity.dh_public)?
            };

            if envelopes.is_empty() {
                return Ok(format!("nothing for {}\n", identity.label));
            }

            let mut out = String::new();
            let mut events = Vec::new();
            for envelope in &envelopes {
                let attested = home
                    .resolve_attested_sender(&envelope.from_label, &envelope.from_verifying_key);
                let message =
                    match envelope.open_verified(&keys, our_pq.as_ref(), attested.as_ref()) {
                        Ok(message) => message,
                        Err(e) => {
                            out.push_str(&format!("[rejected] {e}\n"));
                            continue;
                        }
                    };
                match Payload::decode(&message.body) {
                    Ok(Payload::Text(text)) => {
                        let body = String::from_utf8_lossy(&text).to_string();
                        out.push_str(&format!("--- {} ---\n{body}\n", message.from_label));
                        events.push(Event::message_received(
                            &message.from_label,
                            "direct",
                            text.len(),
                        ));
                    }
                    Ok(Payload::Group { cell_id, .. }) => {
                        out.push_str(&format!(
                            "--- {} ---\n[group message for cell {}: open it in the app to decrypt]\n",
                            message.from_label,
                            hex::encode(cell_id)
                        ));
                    }
                    Ok(Payload::Blob { name, total, .. }) => {
                        out.push_str(&format!(
                            "--- {} ---\n[file {name}, {total} chunk(s)]\n",
                            message.from_label
                        ));
                    }
                    Ok(other) => {
                        out.push_str(&format!(
                            "--- {} ---\n[control payload {other:?}]\n",
                            message.from_label
                        ));
                    }
                    Err(e) => out.push_str(&format!("[payload rejected] {e}\n")),
                }
            }

            let hooks = Webhooks::load(home)?;
            if !hooks.all().is_empty() {
                for event in &events {
                    for delivery in hooks.deliver(event) {
                        if !delivery.ok {
                            eprintln!("webhook {} failed: {:?}", delivery.url, delivery.detail);
                        }
                    }
                }
            }

            out.push_str(&format!("{} message(s)\n", envelopes.len()));
            Ok(out)
        }

        "arnauth_receipt" => {
            let hive = Beehive::load(home)?;
            let receipt = hive.consolidate()?;
            Ok(format!(
                "peers: {}\ncells: {}\nratio: {}\nwire: {}\n",
                receipt.peers,
                receipt.cells,
                receipt.ratio(),
                receipt.wire_hex()
            ))
        }

        other => Err(arnauth_core::Error::Malformed {
            what: "mcp tool",
            detail: format!("no tool named {other:?}"),
        }),
    }
}

fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn home(name: &str) -> Home {
        let dir = std::env::temp_dir().join(format!("arnauth-mcp-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let home = Home::at(dir);
        home.init().unwrap();
        home
    }

    fn call(home: &Home, method: &str, params: Value) -> Value {
        handle(
            home,
            &json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }),
        )
    }

    fn text_of(response: &Value) -> String {
        response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    #[test]
    fn initialize_advertises_tools() {
        let home = home("init");
        let response = call(&home, "initialize", json!({}));
        assert_eq!(response["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(response["result"]["serverInfo"]["name"], "arnauth");
        assert!(response["result"]["capabilities"]["tools"].is_object());
    }

    #[test]
    fn tools_list_names_every_tool_from_the_catalog() {
        let home = home("list");
        let response = call(&home, "tools/list", json!({}));
        let tools = response["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"arnauth_send"));
        assert!(names.contains(&"arnauth_inbox"));
        assert!(names.contains(&"arnauth_whoami"));
        for tool in tools {
            assert!(tool["inputSchema"]["type"] == "object");
        }
    }

    #[test]
    fn whoami_works_once_an_identity_exists() {
        let home = home("whoami");
        home.create("me@mail.com").unwrap();

        let response = call(&home, "tools/call", json!({ "name": "arnauth_whoami" }));
        let text = text_of(&response);
        assert!(text.contains("me@mail.com"), "got {text}");
        assert!(text.contains("seal verified: true"), "got {text}");
        assert!(text.contains("post-quantum keys: yes"), "got {text}");
    }

    #[test]
    fn a_missing_identity_is_a_tool_error_not_a_crash() {
        let home = home("noident");
        let response = call(&home, "tools/call", json!({ "name": "arnauth_whoami" }));
        assert_eq!(response["result"]["isError"], true);
    }

    #[test]
    fn send_then_inbox_round_trips_through_mcp() {
        let home = home("send");
        home.create("alice.eth").unwrap();
        home.create("bob.eth").unwrap();
        home.set_active("alice.eth").unwrap();

        let response = call(
            &home,
            "tools/call",
            json!({
                "name": "arnauth_send",
                "arguments": { "to": "bob.eth", "body": "hello from an agent" }
            }),
        );
        assert_eq!(response["result"]["isError"], false);
        assert!(text_of(&response).contains("hybrid"));

        home.set_active("bob.eth").unwrap();
        let response = call(
            &home,
            "tools/call",
            json!({ "name": "arnauth_inbox", "arguments": { "take": true } }),
        );
        let text = text_of(&response);
        assert!(text.contains("hello from an agent"), "got {text}");
        assert!(text.contains("alice.eth"), "got {text}");
    }

    #[test]
    fn an_unknown_tool_is_reported_as_an_error() {
        let home = home("unknown");
        let response = call(&home, "tools/call", json!({ "name": "arnauth_nope" }));
        assert_eq!(response["result"]["isError"], true);
        assert!(text_of(&response).contains("no tool named"));
    }

    #[test]
    fn an_unknown_method_is_a_jsonrpc_error() {
        let home = home("method");
        let response = call(&home, "tools/explode", json!({}));
        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn receipt_needs_only_a_store() {
        let home = home("receipt");
        let response = call(&home, "tools/call", json!({ "name": "arnauth_receipt" }));
        assert_eq!(response["result"]["isError"], false);
        assert!(text_of(&response).contains("wire:"));
    }
}
