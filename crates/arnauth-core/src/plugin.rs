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
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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

/// Start one plugin with the event on stdin. Output is captured, bounded by the
/// timeout, and trimmed to something a terminal can show.
pub fn run(plugin: &Plugin, event: &Event) -> PluginRun {
    let Some(shell_cmd) = shell_line(plugin) else {
        return PluginRun {
            name: plugin.name.clone(),
            ok: false,
            output: "plugin command is empty".into(),
        };
    };

    let mut child = match Command::new("/bin/sh")
        .arg("-c")
        .arg(&shell_cmd)
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

    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(e) => {
            return PluginRun {
                name: plugin.name.clone(),
                ok: false,
                output: format!("could not wait: {e}"),
            };
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if output.status.success() {
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
                output.status.code().unwrap_or(-1),
                if stderr.is_empty() {
                    String::new()
                } else {
                    format!(": {stderr}")
                }
            )),
        }
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
        text.to_string()
    } else {
        format!("{}… ({} bytes)", &text[..MAX], text.len())
    }
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
    fn arguments_are_quoted_not_split() {
        let mut p = plugin("quoted", "printf", &["*"]);
        p.args = vec!["%s".into(), "a b; rm -rf /".into()];
        let run = run(&p, &Event::message_received("x", "y", 0));
        assert!(run.ok);
        assert_eq!(run.output, "a b; rm -rf /");
    }
}
