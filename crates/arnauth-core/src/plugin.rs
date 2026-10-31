//! Plugins: small programs that react to events.
//!
//! A plugin is a command plus a list of events. When an event fires, Arnauth
//! starts the command, writes the event JSON to its stdin, and reads JSON lines
//! back. That is the whole contract — no shared memory, no ABI, no dynamic
//! loading, so a plugin can be a shell script, a Python file, or another Rust
//! binary.
//!
//! **A plugin runs as you.** Installing one is equivalent to running it, and the
//! registry is deliberately not remote: nothing installs a plugin except a human
//! typing `arnauth plugin add`. Treat an unfamiliar plugin command the way you
//! would treat an unfamiliar shell script.

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::api::Event;
use crate::error::{Error, Result};
use crate::store::Home;

/// How long a plugin may run before it is killed and reported as timed out.
pub const PLUGIN_TIMEOUT_MS: u64 = 10_000;

/// One registered plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plugin {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Event names this plugin wants. `["*"]` means everything.
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

impl Plugin {
    pub fn wants(&self, event: &str) -> bool {
        self.enabled && self.events.iter().any(|want| want == "*" || want == event)
    }
}

/// What happened when a plugin ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginRun {
    pub name: String,
    pub ok: bool,
    /// Trimmed stdout, or the failure reason.
    pub output: String,
}

/// The registry, persisted at `<home>/plugins.json`.
#[derive(Debug, Clone, Default)]
pub struct Plugins {
    path: PathBuf,
    plugins: Vec<Plugin>,
}

impl Plugins {
    pub fn load(home: &Home) -> Result<Self> {
        let path = home.root().join("plugins.json");
        let plugins = match fs::read(&path) {
            Ok(raw) => serde_json::from_slice(&raw).map_err(|e| Error::Codec {
                what: "plugins.json",
                detail: e.to_string(),
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(Error::io(&path, e)),
        };
        Ok(Self { path, plugins })
    }

    pub fn all(&self) -> &[Plugin] {
        &self.plugins
    }

    pub fn get(&self, name: &str) -> Option<&Plugin> {
        self.plugins
            .iter()
            .find(|plugin| plugin.name.eq_ignore_ascii_case(name))
    }

    pub fn add(&mut self, plugin: Plugin) -> Result<&Plugin> {
        if plugin.name.trim().is_empty() {
            return Err(Error::Malformed {
                what: "plugin",
                detail: "a plugin needs a name".into(),
            });
        }
        if plugin.command.trim().is_empty() {
            return Err(Error::Malformed {
                what: "plugin",
                detail: "a plugin needs a command".into(),
            });
        }
        if self.get(&plugin.name).is_some() {
            return Err(Error::AlreadyExists(plugin.name));
        }

        let mut plugin = plugin;
        if plugin.events.is_empty() {
            plugin.events = vec!["*".to_string()];
        }
        self.plugins.push(plugin);
        self.plugins.last().ok_or_else(|| Error::Malformed {
            what: "plugin",
            detail: "push did not stick".into(),
        })
    }

    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.plugins.len();
        self.plugins
            .retain(|plugin| !plugin.name.eq_ignore_ascii_case(name));
        self.plugins.len() != before
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        let mut raw = serde_json::to_vec_pretty(&self.plugins).map_err(|e| Error::Codec {
            what: "plugins.json",
            detail: e.to_string(),
        })?;
        raw.push(b'\n');
        fs::write(&self.path, raw).map_err(|e| Error::io(&self.path, e))
    }

    /// Run every plugin interested in this event. Never fails the caller: a
    /// broken plugin must not stop a message from being read.
    pub fn dispatch(&self, event: &Event) -> Vec<PluginRun> {
        self.plugins
            .iter()
            .filter(|plugin| plugin.wants(&event.kind))
            .map(|plugin| run(plugin, event))
            .collect()
    }
}

/// Start one plugin with the event on stdin. Output is captured, bounded by
/// [`PLUGIN_TIMEOUT_MS`], and trimmed to something a terminal can show.
pub fn run(plugin: &Plugin, event: &Event) -> PluginRun {
    run_with_timeout(plugin, event, PLUGIN_TIMEOUT_MS)
}

/// `run`, with an explicit deadline. A plugin that does not finish in time is
/// killed, because a hanging plugin must not hang the inbox that dispatched it.
pub fn run_with_timeout(plugin: &Plugin, event: &Event, timeout_ms: u64) -> PluginRun {
    let Some(shell_cmd) = shell_line(plugin) else {
        return PluginRun {
            name: plugin.name.clone(),
            ok: false,
            output: "plugin command is empty".into(),
        };
    };

    let mut child = match shell_command(&shell_cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            return PluginRun {
                name: plugin.name.clone(),
                ok: false,
                output: format!("could not start: {e}"),
            };
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        let body = event.body();
        let _ = stdin.write_all(&body);
        let _ = stdin.write_all(b"\n");
        // Dropping stdin closes it, which is how a plugin knows the event ended.
    }

    // Drain both pipes on their own threads. A plugin that writes more than a
    // pipe buffer would otherwise block forever while we poll for exit.
    let stdout_reader = child.stdout.take().map(spawn_reader);
    let stderr_reader = child.stderr.take().map(spawn_reader);

    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1));
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return PluginRun {
                        name: plugin.name.clone(),
                        ok: false,
                        output: format!("timed out after {timeout_ms} ms"),
                    };
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(e) => {
                let _ = child.kill();
                return PluginRun {
                    name: plugin.name.clone(),
                    ok: false,
                    output: format!("could not wait: {e}"),
                };
            }
        }
    };

    let stdout = join_reader(stdout_reader);
    let stderr = join_reader(stderr_reader);

    if status.success() {
        PluginRun {
            name: plugin.name.clone(),
            ok: true,
            output: if stdout.is_empty() {
                "(no output)".to_string()
            } else {
                clip(&stdout)
            },
        }
    } else {
        PluginRun {
            name: plugin.name.clone(),
            ok: false,
            output: clip(&format!(
                "exit {}{}",
                status.code().unwrap_or(-1),
                if stderr.is_empty() {
                    String::new()
                } else {
                    format!(": {stderr}")
                }
            )),
        }
    }
}

fn spawn_reader(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        buf
    })
}

fn join_reader(handle: Option<std::thread::JoinHandle<Vec<u8>>>) -> String {
    match handle.and_then(|h| h.join().ok()) {
        Some(bytes) => String::from_utf8_lossy(&bytes).trim().to_string(),
        None => String::new(),
    }
}

/// `/bin/sh` where it exists, `cmd /C` where it does not. Same contract.
fn shell_command(line: &str) -> Command {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("cmd");
        cmd.args(["/C", line]);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }
    #[cfg(not(windows))]
    {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", line]);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }
}

fn shell_line(plugin: &Plugin) -> Option<String> {
    let mut parts = Vec::with_capacity(plugin.args.len() + 1);
    parts.push(shell_quote(&plugin.command));
    for arg in &plugin.args {
        parts.push(shell_quote(arg));
    }
    let line = parts.join(" ");
    if line.trim().is_empty() {
        None
    } else {
        Some(line)
    }
}

/// Single-quote for `/bin/sh`, which is enough for a command *and* its args.
fn shell_quote(raw: &str) -> String {
    if !raw.is_empty()
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-/:+=@%^,".contains(c))
    {
        return raw.to_string();
    }
    format!("'{}'", raw.replace('\'', r#"'\''"#))
}

fn clip(text: &str) -> String {
    const MAX: usize = 2000;
    if text.len() <= MAX {
        return text.to_string();
    }
    // Never slice through a multi-byte character: a plugin emitting kanji at
    // byte 2000 must not be able to panic the inbox.
    let mut end = MAX;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… ({} bytes)", &text[..end], text.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home(name: &str) -> Home {
        let dir =
            std::env::temp_dir().join(format!("arnauth-plugins-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let home = Home::at(dir);
        home.init().unwrap();
        home
    }

    fn plugin(name: &str, command: &str, events: &[&str]) -> Plugin {
        Plugin {
            name: name.into(),
            command: command.into(),
            args: Vec::new(),
            events: events.iter().map(|e| e.to_string()).collect(),
            description: String::new(),
            enabled: true,
        }
    }

    #[test]
    fn registry_round_trips() {
        let home = home("roundtrip");
        let mut plugins = Plugins::load(&home).unwrap();
        plugins
            .add(plugin("echoer", "/bin/cat", &["message.received"]))
            .unwrap();
        plugins.save().unwrap();

        let loaded = Plugins::load(&home).unwrap();
        assert_eq!(loaded.all().len(), 1);
        assert!(loaded.get("ECHOER").is_some(), "lookup ignores case");
    }

    #[test]
    fn a_plugin_needs_a_name_and_a_command() {
        let home = home("validate");
        let mut plugins = Plugins::load(&home).unwrap();
        assert!(plugins.add(plugin("", "/bin/cat", &[])).is_err());
        assert!(plugins.add(plugin("x", "  ", &[])).is_err());
    }

    #[test]
    fn duplicates_are_refused_and_removable() {
        let home = home("dupes");
        let mut plugins = Plugins::load(&home).unwrap();
        plugins.add(plugin("a", "/bin/cat", &[])).unwrap();
        assert!(plugins.add(plugin("A", "/bin/cat", &[])).is_err());
        assert!(plugins.remove("a"));
        assert!(!plugins.remove("a"));
    }

    #[test]
    fn event_filtering_respects_wildcards() {
        let all = plugin("all", "/bin/cat", &["*"]);
        assert!(all.wants("message.received"));
        assert!(all.wants("blob.completed"));

        let one = plugin("one", "/bin/cat", &["blob.completed"]);
        assert!(one.wants("blob.completed"));
        assert!(!one.wants("message.received"));

        let mut off = one.clone();
        off.enabled = false;
        assert!(!off.wants("blob.completed"), "disabled means disabled");
    }

    #[test]
    fn a_real_plugin_receives_the_event_on_stdin() {
        let echo = plugin("echoer", "/bin/cat", &["*"]);
        let event = Event::message_received("kai.eth", "direct", 7);
        let run = run(&echo, &event);

        assert!(run.ok, "plugin failed: {}", run.output);
        let parsed: serde_json::Value = serde_json::from_str(&run.output).unwrap();
        assert_eq!(parsed["event"], "message.received");
        assert_eq!(parsed["payload"]["from"], "kai.eth");
    }

    #[test]
    fn a_failing_plugin_is_reported_not_fatal() {
        let broken = plugin("broken", "exit 3", &["*"]);
        let run = run(&broken, &Event::message_received("a", "b", 1));
        assert!(!run.ok);
        assert!(run.output.contains("exit 3"), "got {}", run.output);
    }

    fn plugin_with(name: &str, command: &str, args: &[&str], events: &[&str]) -> Plugin {
        Plugin {
            name: name.into(),
            command: command.into(),
            args: args.iter().map(|a| a.to_string()).collect(),
            events: events.iter().map(|e| e.to_string()).collect(),
            description: String::new(),
            enabled: true,
        }
    }

    #[test]
    fn a_hanging_plugin_is_killed_at_the_deadline() {
        let hanging = plugin_with("hang", "sleep", &["30"], &["*"]);
        let started = std::time::Instant::now();

        let run = run_with_timeout(&hanging, &Event::message_received("a", "b", 1), 150);

        assert!(!run.ok);
        assert!(run.output.contains("timed out"), "got {}", run.output);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the deadline must actually bite, took {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_chatty_plugin_does_not_deadlock_on_a_full_pipe() {
        // ~256 KiB of stdout is well past a pipe buffer, so a naive
        // wait-then-read would block forever.
        let chatty = plugin_with(
            "chatty",
            "/bin/sh",
            &["-c", "head -c 262144 /dev/zero | tr '\\0' 'x'"],
            &["*"],
        );
        let run = run_with_timeout(&chatty, &Event::message_received("a", "b", 1), 5_000);

        assert!(run.ok, "chatty plugin failed: {}", run.output);
        assert!(
            run.output.contains("(262144 bytes)"),
            "clipped output should say how much arrived, got {} bytes",
            run.output.len()
        );
        assert!(run.output.len() < 3000, "output should be clipped");
    }

    #[test]
    fn a_missing_command_is_reported() {
        let missing = plugin("missing", "/nonexistent/plugin-binary", &["*"]);
        let run = run(&missing, &Event::message_received("a", "b", 1));
        assert!(!run.ok);
    }

    #[test]
    fn dispatch_only_runs_interested_plugins() {
        let home = home("dispatch");
        let mut plugins = Plugins::load(&home).unwrap();
        plugins
            .add(plugin("cat", "/bin/cat", &["message.received"]))
            .unwrap();
        plugins
            .add(plugin("ignored", "echo nope", &["blob.completed"]))
            .unwrap();

        let runs = plugins.dispatch(&Event::message_received("kai.eth", "direct", 3));
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].name, "cat");
        assert!(runs[0].ok);
    }

    #[test]
    fn clipping_never_splits_a_character() {
        let text = "界".repeat(1500); // 4.5 KB of multi-byte characters
        let clipped = clip(&text);
        assert!(clipped.len() < text.len());
        assert!(clipped.contains("bytes)"));

        let ascii = "x".repeat(10);
        assert_eq!(clip(&ascii), ascii, "short output is untouched");
    }

    #[test]
    fn the_command_is_a_program_not_a_shell_line() {
        // `command` is the executable; spaces belong in `args`. A typo like
        // "sleep 30" must fail loudly instead of being interpreted by a shell.
        let run = run(
            &plugin("typo", "sleep 30", &["*"]),
            &Event::message_received("a", "b", 1),
        );
        assert!(!run.ok, "a spaced command must not be run as a shell line");
    }

    #[test]
    fn arguments_are_quoted_not_split() {
        let mut p = plugin("quoted", "printf", &["*"]);
        p.args = vec!["%s".into(), "a b; rm -rf /".into()];
        let run = run(&p, &Event::message_received("x", "y", 0));
        assert!(run.ok);
        assert_eq!(run.output, "a b; rm -rf /");
    }
}
