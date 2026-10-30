//! Arnauth desktop — one native window over `arnauth-core`.
//!
//! The window is a thin shell: identities come from the store, messages are
//! sealed by the core, and the spool is the only transport. Nothing here invents
//! a rail that does not exist.

use arnauth_core::api::{Event, Webhooks};
use arnauth_core::beehive::{Beehive, Decay};
use arnauth_core::contacts::{ContactCard, Contacts};
use arnauth_core::envelope::Envelope;
use arnauth_core::group;
use arnauth_core::identity::{now_ms, subject_for, Identity};
use arnauth_core::media::{chunk_hash, BlobAssembler, BlobChunk, DEFAULT_CHUNK};
use arnauth_core::payload::Payload;
use arnauth_core::store::Home;
use arnauth_core::transport::Spool;
use eframe::egui;

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 720.0])
            .with_min_inner_size([720.0, 520.0])
            .with_title("Arnauth"),
        ..Default::default()
    };

    eframe::run_native(
        "Arnauth",
        options,
        Box::new(|_cc| Ok(Box::new(App::start()))),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pane {
    Welcome,
    Identity,
    Compose,
    Inbox,
    Swarm,
    Contacts,
}

struct App {
    home: Option<Home>,
    startup_error: Option<String>,
    identities: Vec<Identity>,
    active: Option<String>,
    selected: Option<String>,
    pane: Pane,

    new_label: String,
    compose_to: String,
    compose_body: String,
    compose_cell: Option<String>,
    new_cell_name: String,
    card_paste: String,
    attach_path: String,
    assemblers: std::collections::HashMap<[u8; 32], BlobAssembler>,

    inbox: Vec<InboxRow>,
    log: Vec<String>,
    show_help: bool,
    themed: bool,
}

struct InboxRow {
    channel: String,
    from: String,
    body: String,
    created_ms: u64,
}

impl App {
    fn start() -> Self {
        let mut app = Self {
            home: None,
            startup_error: None,
            identities: Vec::new(),
            active: None,
            selected: None,
            pane: Pane::Identity,
            new_label: String::new(),
            compose_to: String::new(),
            compose_body: String::new(),
            compose_cell: None,
            new_cell_name: String::new(),
            card_paste: String::new(),
            attach_path: String::new(),
            assemblers: Default::default(),
            inbox: Vec::new(),
            log: Vec::new(),
            show_help: false,
            themed: false,
        };

        match Home::discover() {
            Ok(home) => {
                app.home = Some(home);
                app.refresh();
                if app.identities.is_empty() {
                    app.pane = Pane::Welcome;
                }
            }
            Err(e) => app.startup_error = Some(e.to_string()),
        }
        app
    }

    fn refresh(&mut self) {
        let Some(home) = self.home.as_ref().cloned() else {
            return;
        };
        self.identities = home.summary().unwrap_or_default();
        self.active = home.active_label().ok().flatten();
        if self.selected.is_none() {
            self.selected = self.active.clone().or_else(|| {
                self.identities
                    .first()
                    .map(|identity| identity.label.clone())
            });
        }
        if self.compose_cell.is_none() {
            self.compose_cell = Beehive::load(&home)
                .ok()
                .and_then(|hive| hive.cells.first().map(|cell| cell.name.clone()));
        }
        self.refresh_inbox();
    }

    fn refresh_inbox(&mut self) {
        self.inbox.clear();
        let (Some(home), Some(label)) = (self.home.as_ref().cloned(), self.selected.clone()) else {
            return;
        };
        let Ok((identity, keys)) = home.load(&label) else {
            return;
        };
        let our_pq = home.pq(&identity.label).unwrap_or(None);
        let downloads = home.root().join("downloads");
        let envelopes = Spool::new(&home)
            .pending(identity.dh_public)
            .unwrap_or_default();

        let mut hive = Beehive::load(&home).unwrap_or_default();
        let mut changed = false;
        let mut events: Vec<Event> = Vec::new();

        for envelope in envelopes {
            let attested =
                home.resolve_attested_sender(&envelope.from_label, &envelope.from_verifying_key);
            let message = match envelope.open_verified(&keys, our_pq.as_ref(), attested.as_ref()) {
                Ok(message) => message,
                Err(e) => {
                    self.note(format!("rejected envelope: {e}"));
                    continue;
                }
            };
            let payload = match Payload::decode(&message.body) {
                Ok(payload) => payload,
                Err(e) => {
                    self.note(format!("rejected payload: {e}"));
                    continue;
                }
            };

            match payload {
                Payload::Blob {
                    blob_id,
                    index,
                    total,
                    name,
                    kind,
                    data,
                    ..
                } => {
                    let chunk = BlobChunk {
                        blob_id,
                        index,
                        total,
                        name,
                        kind,
                        hash: chunk_hash(&data),
                        data,
                    };
                    let assembler = self
                        .assemblers
                        .entry(blob_id)
                        .or_insert_with(|| BlobAssembler::from_chunk(&chunk));

                    match assembler.accept(&chunk) {
                        Ok(_) if assembler.is_complete() => {
                            if let Some(done) = self.assemblers.remove(&blob_id) {
                                match done.finish() {
                                    Ok(blob) => {
                                        let _ = std::fs::create_dir_all(&downloads);
                                        let target = downloads.join(&blob.name);
                                        match std::fs::write(&target, &blob.bytes) {
                                            Ok(()) => {
                                                self.note(format!(
                                                    "blob {} → {}",
                                                    blob.name,
                                                    target.display()
                                                ));
                                                self.inbox.push(InboxRow {
                                                    channel: format!("file · {}", blob.kind),
                                                    from: message.from_label.clone(),
                                                    body: format!(
                                                        "{} saved ({} bytes)",
                                                        target.display(),
                                                        blob.bytes.len()
                                                    ),
                                                    created_ms: message.created_ms,
                                                });
                                            }
                                            Err(e) => self.note(format!("blob not written: {e}")),
                                        }
                                    }
                                    Err(e) => self.note(format!("blob failed verification: {e}")),
                                }
                            }
                        }
                        Ok(_) => {
                            let (have, total) = (assembler.have(), assembler.total());
                            self.note(format!("blob chunk {have}/{total}"));
                        }
                        Err(e) => self.note(format!("blob chunk rejected: {e}")),
                    }
                }
                Payload::Text(text) => {
                    events.push(Event::message_received(
                        &message.from_label,
                        "direct",
                        text.len(),
                    ));
                    self.inbox.push(InboxRow {
                        channel: "direct".into(),
                        from: message.from_label.clone(),
                        body: String::from_utf8_lossy(&text).into_owned(),
                        created_ms: message.created_ms,
                    })
                }
                Payload::Channel { name, body } => {
                    events.push(Event::message_received(
                        &message.from_label,
                        &name,
                        body.len(),
                    ));
                    self.inbox.push(InboxRow {
                        channel: format!("#{name}"),
                        from: message.from_label.clone(),
                        body: String::from_utf8_lossy(&body).into_owned(),
                        created_ms: message.created_ms,
                    })
                }
                Payload::KeyWrap {
                    cell_id,
                    cell_key,
                    name,
                } => {
                    let subject = subject_for(&message.from_label);
                    match group::install_keywrap(
                        &mut hive,
                        subject,
                        cell_id,
                        cell_key,
                        &name,
                        now_ms(),
                    ) {
                        Ok(()) => {
                            changed = true;
                            self.note(format!("joined cell {name} from {}", message.from_label));
                        }
                        Err(e) => self.note(format!("key handoff refused: {e}")),
                    }
                }
                Payload::Group {
                    cell_id,
                    nonce,
                    body,
                } => {
                    let cell = hive.cells.iter().find(|cell| cell.id == cell_id).cloned();
                    match cell {
                        Some(cell) => {
                            match group::open_body(
                                &cell,
                                &message.from_verifying_key,
                                &nonce,
                                &body,
                            ) {
                                Ok(plain) => self.inbox.push(InboxRow {
                                    channel: cell.name.clone(),
                                    from: message.from_label.clone(),
                                    body: String::from_utf8_lossy(&plain).into_owned(),
                                    created_ms: message.created_ms,
                                }),
                                Err(e) => self.note(format!("group message rejected: {e}")),
                            }
                        }
                        None => self.note("group message for a cell this side has no key for"),
                    }
                }
            }
        }

        if changed {
            let _ = hive.save(&home);
        }

        if !events.is_empty() {
            if let Ok(hooks) = Webhooks::load(&home) {
                if !hooks.all().is_empty() {
                    for event in &events {
                        for delivery in hooks.deliver(event) {
                            if !delivery.ok {
                                self.note(format!(
                                    "webhook {} failed: {:?}",
                                    delivery.url, delivery.detail
                                ));
                            }
                        }
                    }
                }
            }
            if let Ok(plugins) = arnauth_core::plugin::Plugins::load(&home) {
                if !plugins.all().is_empty() {
                    for event in &events {
                        for run in plugins.dispatch(event) {
                            if run.ok {
                                let first = run.output.lines().next().unwrap_or_default();
                                self.note(format!("plugin {} → {first}", run.name));
                            } else {
                                self.note(format!("plugin {} failed: {}", run.name, run.output));
                            }
                        }
                    }
                }
            }
        }
    }

    fn note(&mut self, line: impl Into<String>) {
        self.log.push(line.into());
        if self.log.len() > 200 {
            self.log.drain(0..self.log.len() - 200);
        }
    }

    fn selected_identity(&self) -> Option<&Identity> {
        let label = self.selected.as_ref()?;
        self.identities
            .iter()
            .find(|identity| &identity.label == label)
    }

    fn create_identity(&mut self) {
        let Some(home) = self.home.as_ref().cloned() else {
            return;
        };
        let label = self.new_label.trim().to_string();
        if label.is_empty() {
            self.note("type a label first — an email or a name");
            return;
        }
        match home.create(&label) {
            Ok((identity, _)) => {
                self.note(format!("minted {} ({})", identity.label, identity.kind));
                self.selected = Some(identity.label.clone());
                self.new_label.clear();
                self.refresh();
            }
            Err(e) => self.note(format!("could not mint: {e}")),
        }
    }

    fn send(&mut self) {
        let (Some(home), Some(label)) = (self.home.as_ref().cloned(), self.selected.clone()) else {
            return;
        };
        let body = self.compose_body.trim().to_string();
        if body.is_empty() {
            self.note("a message needs a body");
            return;
        }
        let compose_to = self.compose_to.trim().to_string();

        let attach = self.attach_path.trim().to_string();

        let result = (|| {
            let (identity, keys) = home.load(&label)?;
            let our_pq = home.pq(&identity.label)?;
            let spool = Spool::new(&home);

            if let Some(cell_name) = self.compose_cell.clone() {
                let hive = Beehive::load(&home)?;
                let cell = hive
                    .cell(&cell_name)
                    .ok_or_else(|| arnauth_core::Error::NotFound(cell_name.clone()))?
                    .clone();
                let queued = group::send_with(
                    &cell,
                    &identity,
                    &keys,
                    our_pq.as_ref(),
                    body.as_bytes(),
                    &hive,
                    &spool,
                )?;
                return Ok::<_, arnauth_core::Error>(format!(
                    "sealed for {queued} member(s) of {}",
                    cell.name
                ));
            }

            let recipient = home.resolve_card(&compose_to)?;

            if !attach.is_empty() {
                let path = std::path::PathBuf::from(&attach);
                let bytes = std::fs::read(&path).map_err(|e| arnauth_core::Error::Io {
                    path: path.clone(),
                    source: e,
                })?;
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("blob")
                    .to_string();
                let chunks = arnauth_core::media::split(
                    &name,
                    "application/octet-stream",
                    &bytes,
                    DEFAULT_CHUNK,
                )?;

                for chunk in &chunks {
                    let payload = Payload::Blob {
                        blob_id: chunk.blob_id,
                        index: chunk.index,
                        total: chunk.total,
                        hash: chunk.hash,
                        name: chunk.name.clone(),
                        kind: chunk.kind.clone(),
                        data: chunk.data.clone(),
                    }
                    .encode();
                    let envelope = Envelope::seal_with(
                        &identity,
                        &keys,
                        our_pq.as_ref(),
                        &recipient,
                        &payload,
                    )?;
                    spool.deliver(recipient.dh_public, &envelope)?;
                }
                return Ok(format!(
                    "sent {} ({} chunks, {})",
                    name,
                    chunks.len(),
                    if recipient.is_hybrid_capable() {
                        "hybrid"
                    } else {
                        "classical"
                    }
                ));
            }

            let payload = Payload::Text(body.as_bytes().to_vec()).encode();
            let envelope =
                Envelope::seal_with(&identity, &keys, our_pq.as_ref(), &recipient, &payload)?;
            spool.deliver(recipient.dh_public, &envelope)?;
            Ok(format!(
                "sealed for {} ({})",
                recipient.label,
                if envelope.mode == arnauth_core::envelope::EnvelopeMode::Hybrid {
                    "hybrid"
                } else {
                    "classical"
                }
            ))
        })();

        match result {
            Ok(line) => {
                self.note(line);
                self.compose_body.clear();
            }
            Err(e) => self.note(format!("not sent: {e}")),
        }
    }

    fn trust_card(&mut self) {
        let Some(home) = self.home.as_ref().cloned() else {
            return;
        };
        let parsed = match ContactCard::from_json(self.card_paste.trim()) {
            Ok(card) => card,
            Err(e) => {
                self.note(format!("card rejected: {e}"));
                return;
            }
        };
        let result = (|| {
            let mut contacts = Contacts::load(&home)?;
            let is_new = contacts.upsert(parsed.clone())?;
            contacts.save()?;

            let mut hive = Beehive::load(&home)?;
            hive.learn(parsed.clone(), now_ms())?;
            hive.save(&home)?;
            Ok::<_, arnauth_core::Error>((parsed.label.clone(), is_new))
        })();
        match result {
            Ok((label, is_new)) => {
                self.note(format!(
                    "{} {label}",
                    if is_new { "trusted" } else { "updated" }
                ));
                self.card_paste.clear();
            }
            Err(e) => self.note(format!("address book not written: {e}")),
        }
    }

    fn forget(&mut self) {
        let Some(home) = self.home.as_ref().cloned() else {
            return;
        };
        let mut hive = match Beehive::load(&home) {
            Ok(hive) => hive,
            Err(e) => {
                self.note(format!("hive not readable: {e}"));
                return;
            }
        };
        let before = hive.peers.len();
        let receipt = hive.forget(
            now_ms(),
            Decay {
                half_life_ms: 30 * DAY_MS,
                ..Decay::default()
            },
        );
        match hive.save(&home) {
            Ok(()) => self.note(format!(
                "forgot: {before} -> {} peer(s), {} dropped, {} weight lost",
                hive.peers.len(),
                receipt.peers_dropped,
                receipt.weight_lost
            )),
            Err(e) => self.note(format!("hive not written: {e}")),
        }
        self.refresh_inbox();
    }

    fn new_cell(&mut self) {
        let Some(home) = self.home.as_ref().cloned() else {
            return;
        };
        let name = self.new_cell_name.trim().to_string();
        if name.is_empty() {
            self.note("name the cell first");
            return;
        }
        let result = (|| {
            let mut hive = Beehive::load(&home)?;
            let cell = hive.new_cell(&name, now_ms())?;
            hive.save(&home)?;
            Ok::<_, arnauth_core::Error>(cell.name)
        })();
        match result {
            Ok(name) => {
                self.note(format!("created cell {name}"));
                self.compose_cell = Some(name);
                self.new_cell_name.clear();
            }
            Err(e) => self.note(format!("cell not created: {e}")),
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.themed {
            apply_theme(ctx);
            self.themed = true;
        }

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Arnauth");
                ui.label("talk as an email or a name — no number");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .button("?")
                        .on_hover_text("keyboard shortcuts and what the colours mean")
                        .clicked()
                    {
                        self.show_help = !self.show_help;
                    }
                    if let Some(active) = self.active.clone() {
                        ui.monospace(active);
                    } else {
                        ui.label("no active identity");
                    }
                });
            });
        });

        egui::TopBottomPanel::bottom("log").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("log");
                if ui.small_button("clear").clicked() {
                    self.log.clear();
                }
            });
            egui::ScrollArea::vertical()
                .max_height(110.0)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &self.log {
                        ui.monospace(line);
                    }
                });
        });

        egui::SidePanel::left("identities")
            .resizable(true)
            .default_width(250.0)
            .show(ctx, |ui| {
                ui.heading("identities");
                ui.separator();

                let labels: Vec<(String, bool)> = self
                    .identities
                    .iter()
                    .map(|identity| (identity.label.clone(), identity.verify()))
                    .collect();

                for (label, sealed) in labels {
                    ui.horizontal(|ui| {
                        let selected = self.selected.as_ref() == Some(&label);
                        if ui.selectable_label(selected, &label).clicked() {
                            self.selected = Some(label.clone());
                            self.refresh_inbox();
                        }
                        ui.weak(if sealed { "sealed" } else { "MISMATCH" });
                    });
                }

                if self.identities.is_empty() {
                    ui.weak("nothing yet");
                }

                ui.separator();
                ui.label("mint a new one");
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_label)
                        .hint_text("you@mail.com or kai.eth"),
                );
                if ui.button("mint").clicked() {
                    self.create_identity();
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(error) = self.startup_error.clone() {
                ui.colored_label(egui::Color32::LIGHT_RED, error);
                return;
            }

            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.pane, Pane::Welcome, "start");
                ui.selectable_value(&mut self.pane, Pane::Identity, "identity");
                ui.selectable_value(&mut self.pane, Pane::Compose, "compose");
                ui.selectable_value(&mut self.pane, Pane::Inbox, "inbox");
                ui.selectable_value(&mut self.pane, Pane::Swarm, "swarm");
                ui.selectable_value(&mut self.pane, Pane::Contacts, "contacts");
            });
            ui.separator();

            match self.pane {
                Pane::Welcome => self.welcome_pane(ui),
                Pane::Identity => self.identity_pane(ui),
                Pane::Compose => self.compose_pane(ui),
                Pane::Inbox => self.inbox_pane(ui),
                Pane::Swarm => self.swarm_pane(ui),
                Pane::Contacts => self.contacts_pane(ui),
            }
        });

        if self.show_help {
            let mut open = true;
            egui::Window::new("arnauth — help")
                .open(&mut open)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.heading("what the colours mean");
                    ui.colored_label(egui::Color32::from_rgb(0x00, 0xFF, 0x66), "+1 witnessed");
                    ui.colored_label(egui::Color32::from_rgb(0xFF, 0xD7, 0x00), "0 hold / claimed");
                    ui.colored_label(egui::Color32::from_rgb(0xFF, 0x33, 0x66), "−1 pruned / mismatch");
                    ui.separator();
                    ui.heading("trust ladder");
                    ui.label("claimed  — key proven by a signature, name not");
                    ui.label("attested — you imported their card out of band");
                    ui.label("sealed   — the identity row passes its wupz frame");
                    ui.label("hybrid   — both Ed25519 and ML-DSA-65 verified");
                    ui.separator();
                    ui.heading("store");
                    let root = self
                        .home
                        .as_ref()
                        .map(|home| home.root().display().to_string())
                        .unwrap_or_else(|| "—".into());
                    ui.monospace(root);
                    ui.label("ARNAUTH_HOME relocates it. key.bin is the identity: lose it, lose the identity.");
                });
            if !open {
                self.show_help = false;
            }
        }
    }
}

fn apply_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();

    let void = egui::Color32::from_rgb(0x0B, 0x09, 0x14);
    let panel = egui::Color32::from_rgb(0x10, 0x0D, 0x1C);
    let panel_2 = egui::Color32::from_rgb(0x16, 0x11, 0x2A);
    let primary = egui::Color32::from_rgb(0xFF, 0x6A, 0xC1);
    let structural = egui::Color32::from_rgb(0x00, 0xE5, 0xC9);

    visuals.panel_fill = panel;
    visuals.window_fill = panel;
    visuals.extreme_bg_color = void;
    visuals.faint_bg_color = panel_2;
    visuals.override_text_color = Some(egui::Color32::from_rgb(0xED, 0xE7, 0xF6));
    visuals.hyperlink_color = structural;
    visuals.selection.bg_fill = primary.gamma_multiply(0.35);
    visuals.selection.stroke.color = primary;
    visuals.widgets.active.bg_fill = primary.gamma_multiply(0.45);
    visuals.widgets.hovered.bg_fill = panel_2;
    visuals.widgets.inactive.bg_fill = panel_2;
    visuals.widgets.noninteractive.bg_fill = panel;
    visuals.window_stroke.color = primary.gamma_multiply(0.35);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(10.0, 5.0);
    ctx.set_style(style);
}

impl App {
    fn identity_pane(&mut self, ui: &mut egui::Ui) {
        let Some(identity) = self.selected_identity().cloned() else {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.strong("No identity yet");
                ui.label(
                    "An identity is a label plus a sealed key. Minting one takes a keystroke.",
                );
                if ui.button("open the first-run guide").clicked() {
                    self.pane = Pane::Welcome;
                }
            });
            return;
        };

        ui.heading(&identity.label);
        ui.monospace(format!("kind     {}", identity.kind));
        ui.monospace(format!("subject  {}", hex::encode(identity.subject)));
        ui.monospace(format!("verify   {}", hex::encode(identity.verifying_key)));
        ui.monospace(format!("dh       {}", hex::encode(identity.dh_public)));
        ui.monospace(format!("seal     {}", hex::encode(identity.seal)));

        let pq_line = match self
            .home
            .as_ref()
            .and_then(|home| home.pq(&identity.label).ok().flatten())
        {
            Some(_) => "pq       ml-dsa-65 + ml-kem-768",
            None => "pq       none — classical only",
        };
        ui.monospace(pq_line);

        let sealed = identity.verify();
        ui.colored_label(
            if sealed {
                egui::Color32::LIGHT_GREEN
            } else {
                egui::Color32::LIGHT_RED
            },
            if sealed {
                "wupz seal verified"
            } else {
                "SEAL MISMATCH — the row on disk was edited"
            },
        );

        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("make active").clicked() {
                if let Some(home) = self.home.as_ref().cloned() {
                    match home.set_active(&identity.label) {
                        Ok(()) => {
                            self.active = Some(identity.label.clone());
                            self.note(format!("active: {}", identity.label));
                        }
                        Err(e) => self.note(format!("could not switch: {e}")),
                    }
                }
            }
            if ui.button("copy card").clicked() {
                let card = ContactCard::from_identity(&identity);
                match card.to_json() {
                    Ok(json) => {
                        ui.ctx().copy_text(json);
                        self.note("card copied to clipboard");
                    }
                    Err(e) => self.note(format!("card not built: {e}")),
                }
            }
            if ui.button("refresh inbox").clicked() {
                self.refresh_inbox();
            }
        });

        if self.active.as_deref() == Some(identity.label.as_str()) {
            ui.weak("this is the active identity");
        }
    }

    fn compose_pane(&mut self, ui: &mut egui::Ui) {
        let cells: Vec<String> = self
            .home
            .as_ref()
            .and_then(|home| Beehive::load(home).ok())
            .map(|hive| hive.cells.into_iter().map(|cell| cell.name).collect())
            .unwrap_or_default();

        ui.horizontal(|ui| {
            ui.label("send to");
            ui.selectable_value(&mut self.compose_cell, None, "one person");
            for name in cells {
                ui.selectable_value(&mut self.compose_cell, Some(name.clone()), name);
            }
        });

        if self.compose_cell.is_none() {
            ui.add(
                egui::TextEdit::singleline(&mut self.compose_to)
                    .hint_text("kept in your address book, or one of your own identities"),
            );
        } else {
            ui.weak("one body, encrypted once with the cell key, queued for every member");
        }

        ui.label("body");
        ui.add(
            egui::TextEdit::multiline(&mut self.compose_body)
                .desired_rows(6)
                .desired_width(f32::INFINITY),
        );
        ui.add(
            egui::TextEdit::singleline(&mut self.attach_path)
                .hint_text("attach a file by path — chunked, resumable"),
        );
        ui.horizontal(|ui| {
            if ui.button("seal and spool").clicked() {
                self.send();
            }
            ui.weak("ephemeral X25519 · ChaCha20-Poly1305 · Ed25519");
        });
    }

    fn inbox_pane(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("refresh").clicked() {
                self.refresh_inbox();
            }
            if ui.button("take (delete)").clicked() {
                if let (Some(home), Some(label)) =
                    (self.home.as_ref().cloned(), self.selected.clone())
                {
                    if let Ok((identity, _)) = home.load(&label) {
                        match Spool::new(&home).take(identity.dh_public) {
                            Ok(taken) => self.note(format!("took {} envelope(s)", taken.len())),
                            Err(e) => self.note(format!("queue not cleared: {e}")),
                        }
                    }
                }
                self.refresh_inbox();
            }
            ui.weak(format!("{} waiting", self.inbox.len()));
        });
        ui.separator();

        if self.inbox.is_empty() {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.strong("Nothing here yet");
                ui.label("When someone seals a message for this identity it shows up here.");
                ui.weak(
                    "Send one to yourself to see it work: compose, put your own label in, send.",
                );
                if ui.button("go to compose").clicked() {
                    self.pane = Pane::Compose;
                }
            });
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            for row in &self.inbox {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.monospace(format!(
                        "{} · from {} · {}",
                        row.channel, row.from, row.created_ms
                    ));
                    ui.label(&row.body);
                });
            }
        });
    }

    fn swarm_pane(&mut self, ui: &mut egui::Ui) {
        let hive = self
            .home
            .as_ref()
            .and_then(|home| Beehive::load(home).ok())
            .unwrap_or_default();

        ui.horizontal(|ui| {
            if ui.button("forget (30d half-life)").clicked() {
                self.forget();
            }
            if ui.button("receipt").clicked() {
                match hive.consolidate() {
                    Ok(receipt) => self.note(format!(
                        "hive receipt {} peers={} cells={} ratio={}",
                        receipt.wire_hex(),
                        receipt.peers,
                        receipt.cells,
                        receipt.ratio()
                    )),
                    Err(e) => self.note(format!("receipt failed: {e}")),
                }
            }
            ui.weak(format!(
                "{} peer(s), {} cell(s)",
                hive.peers.len(),
                hive.cells.len()
            ));
        });
        ui.separator();

        let mut peers: Vec<_> = hive.peers.iter().collect();
        peers.sort_by(|a, b| {
            b.weight
                .cmp(&a.weight)
                .then(a.card.label.cmp(&b.card.label))
        });

        egui::ScrollArea::vertical()
            .max_height(280.0)
            .show(ui, |ui| {
                for peer in &peers {
                    ui.horizontal(|ui| {
                        ui.monospace(format!("{:<28}", peer.card.label));
                        ui.monospace(format!("w={:<3}", peer.weight));
                        ui.weak(format!("sent {} · heard {}", peer.sent, peer.heard));
                        if peer.claimed {
                            ui.colored_label(egui::Color32::YELLOW, "claimed");
                        }
                    });
                }

                if peers.is_empty() {
                    ui.label(
                        "No peers yet. The beehive fills as you trust cards and exchange messages.",
                    );
                }
                if !hive.cells.is_empty() {
                    ui.separator();
                    for cell in &hive.cells {
                        ui.monospace(format!(
                            "{:<28} id={} members={} w={}",
                            cell.name,
                            hex::encode(cell.id),
                            cell.members.len(),
                            cell.weight
                        ));
                    }
                }
            });

        ui.separator();
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.new_cell_name)
                    .hint_text("new cell, e.g. saturn.ring"),
            );
            if ui.button("new cell").clicked() {
                self.new_cell();
            }
        });
    }

    fn welcome_pane(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Welcome to Arnauth");
            ui.label("Talk as an email you already own, or a name you mint. No phone number, ever.");
            ui.add_space(6.0);

            let has_identity = !self.identities.is_empty();
            let hive = self
                .home
                .as_ref()
                .and_then(|home| Beehive::load(home).ok())
                .unwrap_or_default();
            let has_peer = !hive.peers.is_empty();
            let has_sent = hive.peers.iter().any(|peer| peer.sent > 0);
            let has_hooks = self
                .home
                .as_ref()
                .and_then(|home| Webhooks::load(home).ok())
                .map(|hooks| !hooks.all().is_empty())
                .unwrap_or(false);
            let has_pq = self
                .home
                .as_ref()
                .and_then(|home| {
                    self.selected
                        .as_ref()
                        .and_then(|label| home.pq(label).ok().flatten())
                        .map(|_| true)
                })
                .unwrap_or(false);

            step_card(ui, 1, "Mint an identity", has_identity, |ui| {
                if has_identity {
                    let label = self.selected.clone().unwrap_or_default();
                    ui.label(format!("you are {}", label));
                    if ui.button("copy my card").clicked() {
                        if let Some(home) = self.home.as_ref().cloned() {
                            if let Ok(card) = home.card(&label) {
                                if let Ok(json) = card.to_json() {
                                    ui.ctx().copy_text(json);
                                    self.note("card copied — send it to the other person");
                                }
                            }
                        }
                    }
                } else {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_label)
                            .hint_text("you@mail.com   or   kai.eth"),
                    );
                    if ui.button("mint it").clicked() {
                        self.create_identity();
                        if !self.identities.is_empty() {
                            self.pane = Pane::Welcome;
                        }
                    }
                    ui.weak("an email you already own, or a name you mint. nothing asks for a number.");
                }
            });

            step_card(ui, 2, "Add someone you can talk to", has_peer, |ui| {
                ui.label("Paste their card, or their whole JSON file contents:");
                ui.add(
                    egui::TextEdit::multiline(&mut self.card_paste)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY)
                        .hint_text(r#"{"label":"kai.eth","kind":"name", ...}"#),
                );
                if ui.button("trust this card").clicked() {
                    self.trust_card();
                }
                ui.weak("their key is proven by their signature; the name is only theirs once you have their card from them.");
            });

            step_card(ui, 3, "Say hello", has_sent, |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.compose_to)
                        .hint_text("who (kai.eth)"),
                );
                ui.add(
                    egui::TextEdit::multiline(&mut self.compose_body)
                        .desired_rows(2)
                        .desired_width(f32::INFINITY)
                        .hint_text("hello"),
                );
                if ui.button("seal and send").clicked() {
                    self.send();
                }
                ui.weak("sealed end-to-end. with post-quantum keys the envelope is hybrid.");
            });

            step_card(ui, 4, "Optional: wire it up", has_hooks || has_pq, |ui| {
                ui.label(if has_pq {
                    "✓ this identity holds ml-dsa-65 + ml-kem-768 keys"
                } else {
                    "· no post-quantum keys in this identity"
                });
                ui.label(if has_hooks {
                    "✓ a webhook is registered"
                } else {
                    "· no webhook yet — `arnauth webhook add http://127.0.0.1:9000/hook`"
                });
                ui.weak("agents drive this store with `arnauth mcp` (stdio JSON-RPC).");
            });

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("identity").clicked() {
                    self.pane = Pane::Identity;
                }
                if ui.button("inbox").clicked() {
                    self.pane = Pane::Inbox;
                }
                if ui.button("swarm").clicked() {
                    self.pane = Pane::Swarm;
                }
                if ui.button("help").clicked() {
                    self.show_help = true;
                }
            });
        });
    }

    fn contacts_pane(&mut self, ui: &mut egui::Ui) {
        let cards = self
            .home
            .as_ref()
            .and_then(|home| Contacts::load(home).ok())
            .map(|contacts| contacts.all().to_vec())
            .unwrap_or_default();

        ui.heading("address book");
        if cards.is_empty() {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label("No cards yet. A card is the public half of someone's identity.");
                ui.weak("Ask them to press \"copy card\" and paste it below.");
            });
        }
        for card in &cards {
            ui.monospace(format!("{:<40} {}", card.label, hex::encode(card.subject)));
        }

        ui.separator();
        ui.label("paste a card");
        ui.add(
            egui::TextEdit::multiline(&mut self.card_paste)
                .desired_rows(6)
                .desired_width(f32::INFINITY)
                .hint_text(r#"{"label":"kai.eth", ...}"#),
        );
        if ui.button("trust").clicked() {
            self.trust_card();
        }
    }
}

/// One numbered step in the first-run flow. A completed step folds its body away
/// so the list stays short, which is the whole point of a checklist.
fn step_card(
    ui: &mut egui::Ui,
    number: usize,
    title: &str,
    done: bool,
    body: impl FnOnce(&mut egui::Ui),
) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.horizontal(|ui| {
            let mark = if done { "✓" } else { "○" };
            let colour = if done {
                egui::Color32::from_rgb(0x00, 0xFF, 0x66)
            } else {
                egui::Color32::from_rgb(0xFF, 0xD7, 0x00)
            };
            ui.colored_label(colour, mark);
            ui.strong(format!("{number}. {title}"));
        });
        if !done {
            ui.add_space(2.0);
            body(ui);
        }
    });
}
