//! Integrations: webhooks, and the shape an agent sees.
//!
//! Two outward faces, on purpose:
//!
//! - **webhooks** for systems — an event lands, a signed JSON POST leaves
//! - **MCP over stdio** for agents — see `arnauth-cli`
//!
//! Webhooks are refreshed per event and signed with HMAC-SHA256 over the exact
//! bytes sent, so a receiver can tell a real delivery from a forged one without
//! trusting the transport.
//!
//! Limitation, stated rather than discovered later: only `http://` is supported.
//! There is no TLS stack in this crate, so a webhook to an `https://` endpoint is
//! refused with a clear error instead of failing mysteriously.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::store::Home;

const SIGNATURE_HEADER: &str = "X-Arnauth-Signature";

/// One registered endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Webhook {
    pub url: String,
    /// Event names this endpoint wants. `["*"]` means everything.
    pub events: Vec<String>,
    /// Shared secret for the HMAC. Generated, never user-supplied.
    pub secret: String,
}

impl Webhook {
    pub fn wants(&self, event: &str) -> bool {
        self.events.iter().any(|want| want == "*" || want == event)
    }
}

/// The registry, persisted at `<home>/webhooks.json` (0600, it holds secrets).
#[derive(Debug, Clone, Default)]
pub struct Webhooks {
    path: PathBuf,
    hooks: Vec<Webhook>,
}

/// Something worth telling the outside world about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub kind: String,
    pub payload: serde_json::Value,
}

impl Event {
    pub fn message_received(from: &str, channel: &str, bytes: usize) -> Self {
        Self {
            kind: "message.received".into(),
            payload: serde_json::json!({
                "from": from,
                "channel": channel,
                "bytes": bytes,
            }),
        }
    }

    pub fn blob_completed(name: &str, kind: &str, bytes: usize, path: &Path) -> Self {
        Self {
            kind: "blob.completed".into(),
            payload: serde_json::json!({
                "name": name,
                "kind": kind,
                "bytes": bytes,
                "path": path.display().to_string(),
            }),
        }
    }

    /// The JSON body a webhook receives.
    pub fn body(&self) -> Vec<u8> {
        let envelope = serde_json::json!({
            "event": self.kind,
            "payload": self.payload,
            "protocol": "arnauth.webhook.v1",
        });
        serde_json::to_vec(&envelope).unwrap_or_else(|_| b"{}".to_vec())
    }
}

impl Webhooks {
    pub fn load(home: &Home) -> Result<Self> {
        let path = home.root().join("webhooks.json");
        let hooks = match fs::read(&path) {
            Ok(raw) => serde_json::from_slice(&raw).map_err(|e| Error::Codec {
                what: "webhooks.json",
                detail: e.to_string(),
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(Error::io(&path, e)),
        };
        Ok(Self { path, hooks })
    }

    pub fn all(&self) -> &[Webhook] {
        &self.hooks
    }

    /// Register an `http://` endpoint. `events` defaults to everything.
    pub fn add(&mut self, url: &str, events: Vec<String>) -> Result<&Webhook> {
        validate_url(url)?;
        if self.hooks.iter().any(|hook| hook.url == url) {
            return Err(Error::AlreadyExists(url.to_string()));
        }

        let events = if events.is_empty() {
            vec!["*".to_string()]
        } else {
            events
        };

        let mut secret = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut secret);

        self.hooks.push(Webhook {
            url: url.to_string(),
            events,
            secret: hex::encode(secret),
        });
        Ok(self.hooks.last().expect("just pushed"))
    }

    pub fn remove(&mut self, url: &str) -> bool {
        let before = self.hooks.len();
        self.hooks.retain(|hook| hook.url != url);
        self.hooks.len() != before
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        let mut raw = serde_json::to_vec_pretty(&self.hooks).map_err(|e| Error::Codec {
            what: "webhooks.json",
            detail: e.to_string(),
        })?;
        raw.push(b'\n');

        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&self.path)
            .map_err(|e| Error::io(&self.path, e))?;
        file.write_all(&raw).map_err(|e| Error::io(&self.path, e))?;
        Ok(())
    }

    /// Fire an event at every interested endpoint. Never fails the caller: a
    /// dead webhook must not break message handling. Returns the delivery log.
    pub fn deliver(&self, event: &Event) -> Vec<Delivery> {
        let body = event.body();
        self.hooks
            .iter()
            .filter(|hook| hook.wants(&event.kind))
            .map(|hook| {
                let signature = sign(&hook.secret, &body);
                let outcome = post_json(&hook.url, &body, &signature);
                Delivery {
                    url: hook.url.clone(),
                    ok: outcome.is_ok(),
                    detail: outcome.err().map(|e| e.to_string()),
                }
            })
            .collect()
    }
}

/// What happened to one webhook attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub url: String,
    pub ok: bool,
    pub detail: Option<String>,
}

/// HMAC-SHA256 of the exact bytes sent, hex encoded.
pub fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

fn validate_url(url: &str) -> Result<()> {
    if url.starts_with("https://") {
        return Err(Error::Malformed {
            what: "webhook url",
            detail: "https is not supported: this crate has no TLS stack. Point the hook at a local relay or an http endpoint."
                .into(),
        });
    }
    if !url.starts_with("http://") {
        return Err(Error::Malformed {
            what: "webhook url",
            detail: "must start with http://".into(),
        });
    }
    let rest = &url["http://".len()..];
    let host = rest.split('/').next().unwrap_or_default();
    if !host.contains(':') {
        return Err(Error::Malformed {
            what: "webhook url",
            detail: "include an explicit port, e.g. http://127.0.0.1:9000/hook".into(),
        });
    }
    Ok(())
}

fn split_http_url(url: &str) -> Result<(String, String)> {
    validate_url(url)?;
    let rest = &url["http://".len()..];
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    Ok((authority.to_string(), path.to_string()))
}

/// A deliberately small HTTP/1.1 POST. One request, one response, no pooling.
pub fn post_json(url: &str, body: &[u8], signature: &str) -> Result<String> {
    let (authority, path) = split_http_url(url)?;
    let mut stream = TcpStream::connect(&authority).map_err(|e| Error::Io {
        path: PathBuf::from(&authority),
        source: e,
    })?;

    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\n{SIGNATURE_HEADER}: {signature}\r\nConnection: close\r\n\r\n",
        len = body.len()
    );

    stream.write_all(head.as_bytes()).map_err(http_io)?;
    stream.write_all(body).map_err(http_io)?;
    stream.flush().map_err(http_io)?;

    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    reader.read_line(&mut status).map_err(http_io)?;
    if !status.contains(" 2") {
        return Err(Error::Malformed {
            what: "webhook",
            detail: format!("endpoint answered {:?}", status.trim_end()),
        });
    }

    // Drain the body so the socket closes cleanly; the content is not used.
    let mut sink = Vec::new();
    let mut rest = Vec::new();
    let _ = reader.read_to_end(&mut rest);
    sink.extend_from_slice(&rest);
    Ok(status.trim_end().to_string())
}

fn http_io(e: std::io::Error) -> Error {
    Error::Io {
        path: PathBuf::from("<webhook>"),
        source: e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn home(name: &str) -> Home {
        let dir = std::env::temp_dir().join(format!("arnauth-hooks-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let home = Home::at(dir);
        home.init().unwrap();
        home
    }

    #[test]
    fn a_hook_round_trips_through_the_registry() {
        let home = home("roundtrip");
        let mut hooks = Webhooks::load(&home).unwrap();
        hooks.add("http://127.0.0.1:9/hook", vec![]).unwrap();
        hooks.save().unwrap();

        let loaded = Webhooks::load(&home).unwrap();
        assert_eq!(loaded.all().len(), 1);
        assert_eq!(loaded.all()[0].events, vec!["*".to_string()]);
        assert_eq!(loaded.all()[0].secret.len(), 64);
    }

    #[test]
    fn https_is_refused_with_an_explanation() {
        let home = home("https");
        let mut hooks = Webhooks::load(&home).unwrap();
        let err = hooks.add("https://example.com/hook", vec![]).unwrap_err();
        assert!(err.to_string().contains("TLS"), "got {err}");
    }

    #[test]
    fn a_url_without_a_port_is_refused() {
        let home = home("noport");
        let mut hooks = Webhooks::load(&home).unwrap();
        assert!(hooks.add("http://example.com/hook", vec![]).is_err());
    }

    #[test]
    fn duplicate_urls_are_refused_and_removable() {
        let home = home("dupes");
        let mut hooks = Webhooks::load(&home).unwrap();
        hooks.add("http://127.0.0.1:9/a", vec![]).unwrap();
        assert!(hooks.add("http://127.0.0.1:9/a", vec![]).is_err());
        assert!(hooks.remove("http://127.0.0.1:9/a"));
        assert!(!hooks.remove("http://127.0.0.1:9/a"));
    }

    #[test]
    fn event_filtering_is_exact() {
        let hook = Webhook {
            url: "http://127.0.0.1:9/x".into(),
            events: vec!["blob.completed".into()],
            secret: "00".into(),
        };
        assert!(hook.wants("blob.completed"));
        assert!(!hook.wants("message.received"));
    }

    #[test]
    fn signatures_are_stable_and_body_bound() {
        let a = sign("secret", b"one");
        assert_eq!(a, sign("secret", b"one"));
        assert_ne!(a, sign("secret", b"two"));
        assert_ne!(a, sign("other", b"one"));
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn a_hook_receives_a_signed_post() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if line == "\r\n" {
                        break;
                    }
                    head.push_str(&line);
                }

                let len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; len];
                reader.read_exact(&mut body).unwrap();

                let sig = head
                    .lines()
                    .find_map(|l| l.strip_prefix("X-Arnauth-Signature: "))
                    .unwrap_or_default()
                    .trim()
                    .to_string();

                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                let _ = tx.send((head, body, sig));
            }
        });

        let home = home("deliver");
        let mut hooks = Webhooks::load(&home).unwrap();
        let url = format!("http://{addr}/hook");
        hooks.add(&url, vec![]).unwrap();

        let event = Event::message_received("kai.eth", "direct", 12);
        let log = hooks.deliver(&event);
        assert_eq!(log.len(), 1);
        assert!(log[0].ok, "delivery failed: {:?}", log[0].detail);

        let (head, body, sig) = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert!(head.starts_with("POST /hook HTTP/1.1"));
        assert_eq!(sig, sign(&hooks.all()[0].secret, &body));

        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["event"], "message.received");
        assert_eq!(parsed["payload"]["from"], "kai.eth");
    }

    #[test]
    fn a_dead_endpoint_is_a_logged_failure_not_a_panic() {
        let home = home("dead");
        let mut hooks = Webhooks::load(&home).unwrap();
        hooks.add("http://127.0.0.1:1/dead", vec![]).unwrap();

        let log = hooks.deliver(&Event::message_received("a", "b", 1));
        assert_eq!(log.len(), 1);
        assert!(!log[0].ok);
        assert!(log[0].detail.is_some());
    }

    #[test]
    fn hooks_are_world_unreadable() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let home = home("perms");
            let mut hooks = Webhooks::load(&home).unwrap();
            hooks.add("http://127.0.0.1:9/x", vec![]).unwrap();
            hooks.save().unwrap();

            let mode = fs::metadata(home.root().join("webhooks.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "webhooks hold secrets");
        }
    }
}
