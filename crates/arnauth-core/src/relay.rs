//! A relay: one dumb store-and-forward node.
//!
//! The spool in `transport` is a directory you move yourself. This is the next
//! step: a process that holds queues in memory and hands them out, so two peers
//! on different machines can meet without a shared filesystem.
//!
//! Deliberately dumb:
//!
//! - **no disk**, **no logs** — a restarted relay forgets everything, which is
//!   the correct failure mode for a courier
//! - **no auth** — envelopes are already sealed and signed; a relay that could
//!   read a queue would be a relay you have to trust
//! - **bounded queues** — the oldest frame is dropped first, so one peer that
//!   stops reading cannot exhaust the node
//!
//! Protocol (line-oriented, one connection per exchange):
//!
//! ```text
//! PUT <queue-hex> <len>\n <len raw bytes>  → OK\n
//! GET <queue-hex>\n                        → OK <n>\n (n × "<len>\n<bytes>"), then drained
//! ```

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};

/// Frames kept per queue before the oldest is dropped.
pub const DEFAULT_QUEUE_CAP: usize = 512;

/// Largest single frame the relay will accept. A 64 KiB media chunk hexed is
/// ~128 KiB of JSON, so this leaves room for a full chunk plus header.
pub const MAX_FRAME: usize = 4 * 1024 * 1024;

type Queues = Arc<Mutex<HashMap<String, VecDeque<Vec<u8>>>>>;

/// A running relay. Dropping it does not stop the accept thread; the thread is
/// detached and ends with the process.
pub struct RelayServer {
    addr: SocketAddr,
}

impl RelayServer {
    /// Bind and start accepting. Port `0` picks a free port, which is what the
    /// tests use.
    pub fn start(bind: &str, cap: usize) -> Result<Self> {
        let listener = TcpListener::bind(bind).map_err(|e| Error::Io {
            path: std::path::PathBuf::from(bind),
            source: e,
        })?;
        Self::serve(listener, cap)
    }

    pub fn serve(listener: TcpListener, cap: usize) -> Result<Self> {
        let addr = listener.local_addr().map_err(|e| Error::Io {
            path: std::path::PathBuf::from("<relay>"),
            source: e,
        })?;
        let queues: Queues = Arc::new(Mutex::new(HashMap::new()));
        let cap = cap.max(1);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let queues = Arc::clone(&queues);
                std::thread::spawn(move || {
                    // One bad client closes one connection. Nothing else.
                    let _ = handle(stream, &queues, cap);
                });
            }
        });

        Ok(Self { addr })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

fn handle(mut stream: TcpStream, queues: &Queues, cap: usize) -> Result<()> {
    let peer_reader = stream.try_clone().map_err(relay_io)?;
    let mut reader = BufReader::new(peer_reader);
    let mut line = String::new();

    if reader.read_line(&mut line).map_err(relay_io)? == 0 {
        return Ok(());
    }

    let mut parts = line.trim_end().splitn(3, ' ');
    let verb = parts.next().unwrap_or_default();
    let queue = parts.next().unwrap_or_default();
    let rest = parts.next().unwrap_or_default();

    if !is_queue_name(queue) {
        let _ = stream.write_all(b"ERR queue\n");
        return Ok(());
    }

    match verb {
        "PUT" => {
            let len: usize = rest.parse().map_err(|_| Error::Malformed {
                what: "relay frame",
                detail: format!("bad length {rest:?}"),
            })?;
            if len == 0 || len > MAX_FRAME {
                let _ = stream.write_all(b"ERR length\n");
                return Ok(());
            }

            let mut frame = vec![0u8; len];
            reader.read_exact(&mut frame).map_err(relay_io)?;

            let mut queues = queues.lock().map_err(|_| relay_poisoned())?;
            let queue = queues.entry(queue.to_string()).or_default();
            queue.push_back(frame);
            while queue.len() > cap {
                queue.pop_front();
            }
            drop(queues);

            stream.write_all(b"OK\n").map_err(relay_io)?;
        }

        "GET" => {
            // GET drains: a courier that re-serves a delivery every poll is a
            // courier that never stops talking.
            let frames: Vec<Vec<u8>> = {
                let mut queues = queues.lock().map_err(|_| relay_poisoned())?;
                queues
                    .remove(queue)
                    .map(|queue| queue.into_iter().collect())
                    .unwrap_or_default()
            };

            writeln!(stream, "OK {}", frames.len()).map_err(relay_io)?;
            for frame in frames {
                writeln!(stream, "{}", frame.len()).map_err(relay_io)?;
                stream.write_all(&frame).map_err(relay_io)?;
            }
            stream.flush().map_err(relay_io)?;
        }

        _ => {
            let _ = stream.write_all(b"ERR verb\n");
        }
    }

    Ok(())
}

fn is_queue_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

fn relay_io(e: std::io::Error) -> Error {
    Error::Io {
        path: std::path::PathBuf::from("<relay>"),
        source: e,
    }
}

fn relay_poisoned() -> Error {
    Error::Malformed {
        what: "relay",
        detail: "queue lock poisoned by a panicking handler".into(),
    }
}

/// The client half. One connection per call: simple beats clever for a courier.
#[derive(Debug, Clone)]
pub struct RelayClient {
    addr: SocketAddr,
}

impl RelayClient {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Push one frame into a queue.
    pub fn push(&self, queue: &[u8; 32], frame: &[u8]) -> Result<()> {
        if frame.is_empty() {
            return Err(Error::Malformed {
                what: "relay frame",
                detail: "refusing to push an empty frame".into(),
            });
        }

        let mut stream = TcpStream::connect(self.addr).map_err(relay_io)?;
        writeln!(stream, "PUT {} {}", hex::encode(queue), frame.len()).map_err(relay_io)?;
        stream.write_all(frame).map_err(relay_io)?;
        stream.flush().map_err(relay_io)?;

        let mut status = String::new();
        BufReader::new(stream)
            .read_line(&mut status)
            .map_err(relay_io)?;

        expect_ok(&status)
    }

    /// Pull every frame waiting in a queue.
    pub fn pull(&self, queue: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
        let stream = TcpStream::connect(self.addr).map_err(relay_io)?;
        let mut writer = stream.try_clone().map_err(relay_io)?;
        let mut reader = BufReader::new(stream);

        writeln!(writer, "GET {}", hex::encode(queue)).map_err(relay_io)?;
        writer.flush().map_err(relay_io)?;

        let mut header = String::new();
        reader.read_line(&mut header).map_err(relay_io)?;
        let count = expect_count(&header)?;

        let mut frames = Vec::with_capacity(count);
        for _ in 0..count {
            let mut len_line = String::new();
            reader.read_line(&mut len_line).map_err(relay_io)?;
            let len: usize = len_line.trim().parse().map_err(|_| Error::Malformed {
                what: "relay frame",
                detail: format!("bad length line {len_line:?}"),
            })?;
            let mut frame = vec![0u8; len];
            reader.read_exact(&mut frame).map_err(relay_io)?;
            frames.push(frame);
        }
        Ok(frames)
    }
}

fn expect_ok(line: &str) -> Result<()> {
    let line = line.trim_end();
    if line == "OK" {
        Ok(())
    } else {
        Err(Error::Malformed {
            what: "relay",
            detail: format!("relay said {line:?}"),
        })
    }
}

fn expect_count(line: &str) -> Result<usize> {
    let line = line.trim_end();
    let rest = line.strip_prefix("OK ").ok_or_else(|| Error::Malformed {
        what: "relay",
        detail: format!("relay said {line:?}"),
    })?;
    rest.parse().map_err(|_| Error::Malformed {
        what: "relay",
        detail: format!("relay sent a bad count {rest:?}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(cap: usize) -> (RelayServer, RelayClient) {
        let server = RelayServer::start("127.0.0.1:0", cap).expect("relay binds");
        let client = RelayClient::new(server.addr());
        (server, client)
    }

    #[test]
    fn push_then_pull() {
        let (_server, client) = relay(8);
        let queue = [7u8; 32];

        client.push(&queue, b"first").unwrap();
        client.push(&queue, b"second").unwrap();

        let frames = client.pull(&queue).unwrap();
        assert_eq!(frames, vec![b"first".to_vec(), b"second".to_vec()]);

        // A second poll finds nothing: GET drains.
        assert!(client.pull(&queue).unwrap().is_empty());
    }

    #[test]
    fn queues_are_isolated() {
        let (_server, client) = relay(8);
        let alice = [1u8; 32];
        let bob = [2u8; 32];

        client.push(&alice, b"for alice").unwrap();
        assert!(client.pull(&bob).unwrap().is_empty());
        assert_eq!(client.pull(&alice).unwrap(), vec![b"for alice".to_vec()]);
    }

    #[test]
    fn an_unknown_queue_is_empty_not_an_error() {
        let (_server, client) = relay(8);
        assert!(client.pull(&[9u8; 32]).unwrap().is_empty());
    }

    #[test]
    fn queue_cap_drops_oldest() {
        let (_server, client) = relay(2);
        let queue = [3u8; 32];

        for i in 0..5 {
            client
                .push(&queue, format!("frame-{i}").as_bytes())
                .unwrap();
        }

        let frames = client.pull(&queue).unwrap();
        assert_eq!(frames.len(), 2, "the cap is enforced");
        assert_eq!(frames[0], b"frame-3");
        assert_eq!(frames[1], b"frame-4");
    }

    #[test]
    fn malformed_frame_does_not_kill_the_server() {
        let (server, client) = relay(8);

        // A naked connection that sends gibberish.
        {
            let mut socket = TcpStream::connect(server.addr()).unwrap();
            socket.write_all(b"NONSENSE not-a-queue\n").unwrap();
            let mut reply = String::new();
            use std::io::Read as _;
            let _ = socket.read_to_string(&mut reply);
        }

        // A frame that claims more bytes than it sends.
        {
            let mut socket = TcpStream::connect(server.addr()).unwrap();
            socket
                .write_all(&[b"PUT ", &[b'a'; 64][..], b" 99999999999\n"].concat())
                .unwrap();
        }

        // The relay still works.
        let queue = [4u8; 32];
        client.push(&queue, b"still alive").unwrap();
        assert_eq!(client.pull(&queue).unwrap(), vec![b"still alive".to_vec()]);
    }

    #[test]
    fn a_bad_queue_name_is_refused() {
        let (server, _client) = relay(8);
        let mut socket = TcpStream::connect(server.addr()).unwrap();
        socket.write_all(b"GET ../../etc/passwd\n").unwrap();
        let mut reply = String::new();
        {
            use std::io::Read as _;
            socket.read_to_string(&mut reply).unwrap();
        }
        assert!(reply.starts_with("ERR"), "got {reply:?}");
    }

    #[test]
    fn empty_frames_are_refused_by_the_client() {
        let (_server, client) = relay(8);
        assert!(client.push(&[0u8; 32], b"").is_err());
    }
}
