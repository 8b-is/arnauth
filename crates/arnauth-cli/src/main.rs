//! `arnauth` — the headless half. Everything the GUI does, minus the pixels.

use std::path::PathBuf;
use std::process::ExitCode;

use arnauth_core::beehive::{Beehive, Decay, Learned, SwarmDelta};
use arnauth_core::contacts::{ContactCard, Contacts};
use arnauth_core::envelope::Envelope;
use arnauth_core::group;
use arnauth_core::identity::{now_ms, parse_label, subject_for, Identity};
use arnauth_core::media::{chunk_hash, BlobAssembler, BlobChunk, DEFAULT_CHUNK};
use arnauth_core::payload::Payload;
use arnauth_core::relay::{RelayClient, RelayServer};
use arnauth_core::store::Home;
use arnauth_core::transport::Spool;
use arnauth_core::{Error, IdentityKind, OpenedEnvelope, Result};

use clap::{Parser, Subcommand};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Parser)]
#[command(
    name = "arnauth",
    about = "Talk as an email you already own, or a name you mint. No number.",
    version
)]
struct Cli {
    /// Store root. Defaults to $ARNAUTH_HOME, then ~/.arnauth.
    #[arg(long, global = true, value_name = "DIR")]
    home: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Mint a new identity and make it active.
    Init { label: String },

    /// List identities in the store, marking the active one.
    Identities,

    /// Print the active identity, its seal, and whether the seal verifies.
    Whoami,

    /// Switch the active identity.
    Use { label: String },

    /// Re-verify the seal on one identity, or on every identity.
    Verify { label: Option<String> },

    /// Print the public contact card for a label.
    Card { label: String },

    /// Attest a contact card: write it to the address book and learn it.
    Trust { card: String },

    /// List the address book.
    Contacts,

    /// Seal a message into the recipient's spool queue.
    Send {
        to: String,
        #[arg(default_value = "")]
        body: String,
        /// Sender label. Defaults to the active identity.
        #[arg(long)]
        from: Option<String>,
        /// Attach a file as a chunked blob instead of sending text.
        #[arg(long, value_name = "PATH")]
        file: Option<PathBuf>,
        /// Deliver through a relay instead of the local spool.
        #[arg(long, value_name = "ADDR")]
        via: Option<String>,
    },

    /// Open the active identity's queue. --take removes it afterwards.
    Inbox {
        #[arg(long)]
        take: bool,
        /// Pull from a relay instead of the local spool.
        #[arg(long, value_name = "ADDR")]
        via: Option<String>,
        /// Where completed blobs are written. Defaults to <home>/downloads.
        #[arg(long, value_name = "DIR")]
        save: Option<PathBuf>,
    },

    /// Run a relay: memory only, no disk, no logs.
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },

    /// Print the wupz seal frame of an identity as hex.
    Seal { label: Option<String> },

    /// The beehive: peers, weights, forgetting, and sharing.
    Swarm {
        #[command(subcommand)]
        command: SwarmCommand,
    },

    /// Groups: one cell key, handed to each member sealed 1:1.
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
}

#[derive(Subcommand)]
enum RelayCommand {
    /// Serve queues over TCP.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8795")]
        bind: String,
        /// Frames kept per queue before the oldest is dropped.
        #[arg(long, default_value_t = arnauth_core::relay::DEFAULT_QUEUE_CAP)]
        cap: usize,
    },
}

#[derive(Subcommand)]
enum SwarmCommand {
    /// List peers by weight, plus every cell.
    Show,

    /// Export a sealed delta of cards (no weights, no keys).
    Share {
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },

    /// Absorb a delta produced by another hive.
    Absorb { path: PathBuf },

    /// Halve weight per half-life and drop what falls below the floor.
    Forget {
        #[arg(long, default_value_t = 30)]
        half_life_days: u64,
    },

    /// Seal the whole hive into a 64-byte frame and print it.
    Receipt,
}

#[derive(Subcommand)]
enum GroupCommand {
    /// Create a cell with a fresh key.
    New { name: String },

    /// Put a learned peer in a cell. This does not hand out the key.
    Add { cell: String, member: String },

    /// Hand the cell key to one member, sealed 1:1.
    Invite {
        cell: String,
        member: String,
        #[arg(long)]
        from: Option<String>,
    },

    /// Seal one body once with the cell key and queue it for every member.
    Send {
        cell: String,
        body: String,
        #[arg(long)]
        from: Option<String>,
    },

    /// List cells and their members.
    List,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("arnauth: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let home = match cli.home {
        Some(root) => Home::at(root),
        None => Home::discover()?,
    };

    match cli.command {
        Command::Init { label } => {
            let (identity, _) = home.create(&label)?;
            println!("{}", identity.label);
            println!("  kind    {}", identity.kind);
            println!("  subject {}", hex::encode(identity.subject));
            println!("  verify  {}", hex::encode(identity.verifying_key));
            println!("  dh      {}", hex::encode(identity.dh_public));
            println!("  seal    {}", hex::encode(identity.seal));
            println!("  store   {}", home.identity_dir(&identity.label).display());
        }

        Command::Identities => {
            let active = home.active_label()?;
            let labels = home.labels()?;
            if labels.is_empty() {
                println!("no identities yet — run `arnauth init <label>`");
                return Ok(());
            }
            for label in labels {
                let mark = if Some(&label) == active.as_ref() {
                    "*"
                } else {
                    " "
                };
                let status = match home.load(&label) {
                    Ok((identity, _)) if identity.verify() => "sealed",
                    Ok(_) => "SEAL MISMATCH",
                    Err(_) => "unreadable",
                };
                println!("{mark} {label:<40} {status}");
            }
        }

        Command::Whoami => {
            let (identity, _) = home.active()?;
            print_identity(&identity);
            println!("  verified {}", identity.verify());
        }

        Command::Use { label } => {
            home.set_active(&label)?;
            println!("active: {}", label.trim().to_ascii_lowercase());
        }

        Command::Verify { label } => match label {
            Some(label) => {
                let (identity, _) = home.load(&label)?;
                println!(
                    "{} {}",
                    identity.label,
                    if identity.verify() { "ok" } else { "MISMATCH" }
                );
            }
            None => {
                let mut bad = 0usize;
                for identity in home.summary()? {
                    let ok = identity.verify();
                    if !ok {
                        bad += 1;
                    }
                    println!(
                        "{:<40} {}",
                        identity.label,
                        if ok { "ok" } else { "MISMATCH" }
                    );
                }
                if bad > 0 {
                    eprintln!("{bad} identity/identities failed verification");
                    std::process::exit(1);
                }
            }
        },

        Command::Card { label } => {
            let card = home.resolve_card(&label)?;
            println!("{}", card.to_json()?);
        }

        Command::Trust { card } => {
            let text = if std::path::Path::new(&card).is_file() {
                std::fs::read_to_string(&card).map_err(|e| Error::Io {
                    path: PathBuf::from(&card),
                    source: e,
                })?
            } else {
                card
            };
            let parsed = ContactCard::from_json(&text)?;

            let mut contacts = Contacts::load(&home)?;
            let is_new = contacts.upsert(parsed.clone())?;
            contacts.save()?;

            let mut hive = Beehive::load(&home)?;
            let learned = hive.learn(parsed.clone(), now_ms())?;
            hive.save(&home)?;

            println!(
                "{} {} ({})",
                if is_new { "trusted" } else { "updated" },
                parsed.label,
                match learned {
                    Learned::New => "new peer",
                    Learned::Refreshed => "weight up",
                    Learned::Replaced => "keys replaced",
                }
            );
        }

        Command::Contacts => {
            let contacts = Contacts::load(&home)?;
            if contacts.all().is_empty() {
                println!("address book is empty — `arnauth trust <card.json>`");
                return Ok(());
            }
            for card in contacts.all() {
                println!("{:<40} {}", card.label, hex::encode(card.subject));
            }
        }

        Command::Send {
            to,
            body,
            from,
            file,
            via,
        } => {
            let (identity, keys) = match from {
                Some(label) => home.load(&label)?,
                None => home.active()?,
            };
            let our_pq = home.pq(&identity.label)?;
            let recipient = home.resolve_card(&to)?;

            let payloads: Vec<Vec<u8>> = match file {
                Some(path) => {
                    let bytes = std::fs::read(&path).map_err(|e| Error::Io {
                        path: path.clone(),
                        source: e,
                    })?;
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("blob");
                    let kind = guess_mime(name);
                    let chunks = arnauth_core::media::split(name, kind, &bytes, DEFAULT_CHUNK)?;
                    println!(
                        "{} → {} chunk(s), {} bytes",
                        name,
                        chunks.len(),
                        bytes.len()
                    );
                    chunks.iter().map(blob_payload).collect()
                }
                None => {
                    if body.trim().is_empty() {
                        return Err(Error::Malformed {
                            what: "message",
                            detail: "needs a body or --file".into(),
                        });
                    }
                    vec![Payload::Text(body.into_bytes()).encode()]
                }
            };

            let mut envelopes = Vec::with_capacity(payloads.len());
            for payload in payloads {
                envelopes.push(Envelope::seal_with(
                    &identity,
                    &keys,
                    our_pq.as_ref(),
                    &recipient,
                    &payload,
                )?);
            }

            match via {
                Some(addr) => {
                    let client = RelayClient::new(parse_addr(&addr)?);
                    for envelope in &envelopes {
                        let frame = serde_json::to_vec(envelope).map_err(|e| Error::Codec {
                            what: "envelope",
                            detail: e.to_string(),
                        })?;
                        client.push(&recipient.dh_public, &frame)?;
                    }
                    println!(
                        "{} envelope(s) pushed to relay {} for {}",
                        envelopes.len(),
                        addr,
                        recipient.label
                    );
                }
                None => {
                    let spool = Spool::new(&home);
                    for envelope in &envelopes {
                        spool.deliver(recipient.dh_public, envelope)?;
                    }
                    println!(
                        "{} envelope(s) sealed for {} ({})",
                        envelopes.len(),
                        recipient.label,
                        if recipient.is_hybrid_capable() {
                            "hybrid"
                        } else {
                            "classical"
                        }
                    );
                }
            }

            let mut hive = Beehive::load(&home)?;
            hive.learn(recipient.clone(), now_ms())?;
            hive.touch(&recipient.subject, true, now_ms());
            hive.save(&home)?;
        }

        Command::Inbox { take, via, save } => {
            let (identity, keys) = home.active()?;
            let our_pq = home.pq(&identity.label)?;
            let spool = Spool::new(&home);

            let envelopes: Vec<Envelope> = match &via {
                Some(addr) => {
                    let client = RelayClient::new(parse_addr(addr)?);
                    let frames = client.pull(&identity.dh_public)?;
                    frames
                        .iter()
                        .map(|frame| {
                            serde_json::from_slice(frame).map_err(|e| Error::Codec {
                                what: "envelope",
                                detail: e.to_string(),
                            })
                        })
                        .collect::<Result<Vec<Envelope>>>()?
                }
                None => {
                    if take {
                        spool.take(identity.dh_public)?
                    } else {
                        spool.pending(identity.dh_public)?
                    }
                }
            };

            if envelopes.is_empty() {
                println!("nothing for {}", identity.label);
                return Ok(());
            }

            let save_dir = save.unwrap_or_else(|| home.root().join("downloads"));
            let mut hive = Beehive::load(&home)?;
            let mut opened = 0usize;
            let mut joined = 0usize;
            let mut blobs_done = 0usize;
            let mut assemblers: std::collections::HashMap<[u8; 32], BlobAssembler> =
                Default::default();

            for envelope in &envelopes {
                let message = match envelope.open_any(&keys, our_pq.as_ref()) {
                    Ok(message) => message,
                    Err(e) => {
                        eprintln!("rejected one envelope: {e}");
                        continue;
                    }
                };
                opened += 1;

                let payload = match Payload::decode(&message.body) {
                    Ok(payload) => payload,
                    Err(e) => {
                        eprintln!("rejected one payload: {e}");
                        continue;
                    }
                };

                let sender = claimed_card(&message);
                if sender.label != identity.label {
                    hive.learn_claimed(sender.clone(), now_ms())?;
                    hive.touch(&sender.subject, false, now_ms());
                }

                match payload {
                    Payload::Text(text) => {
                        println!("--- from {} ({})", message.from_label, message.created_ms);
                        println!("{}", String::from_utf8_lossy(&text));
                    }
                    Payload::KeyWrap {
                        cell_id,
                        cell_key,
                        name,
                    } => {
                        arnauth_core::group::install_keywrap(
                            &mut hive,
                            sender.subject,
                            cell_id,
                            cell_key,
                            &name,
                            now_ms(),
                        )?;
                        joined += 1;
                        println!(
                            "joined cell {} (key handed over by {})",
                            name, message.from_label
                        );
                    }
                    Payload::Group {
                        cell_id,
                        nonce,
                        body,
                    } => {
                        let cell = hive.cells.iter().find(|cell| cell.id == cell_id).cloned();
                        match cell {
                            Some(cell) => match arnauth_core::group::open_body(
                                &cell,
                                &message.from_verifying_key,
                                &nonce,
                                &body,
                            ) {
                                Ok(plain) => {
                                    println!(
                                        "--- {} from {} ({})",
                                        cell.name, message.from_label, message.created_ms
                                    );
                                    println!("{}", String::from_utf8_lossy(&plain));
                                }
                                Err(e) => eprintln!("group message rejected: {e}"),
                            },
                            None => eprintln!(
                                "group message for an unknown cell {} — no key here",
                                hex::encode(cell_id)
                            ),
                        }
                    }
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
                            name: name.clone(),
                            kind: kind.clone(),
                            hash: chunk_hash(&data),
                            data,
                        };

                        let assembler = assemblers
                            .entry(blob_id)
                            .or_insert_with(|| BlobAssembler::from_chunk(&chunk));
                        match assembler.accept(&chunk) {
                            Ok(_) => {
                                if assembler.is_complete() {
                                    let done = assemblers
                                        .remove(&blob_id)
                                        .expect("entry exists")
                                        .finish()?;
                                    let target = unique_path(&save_dir, &done.name)?;
                                    std::fs::create_dir_all(&save_dir).map_err(|e| Error::Io {
                                        path: save_dir.clone(),
                                        source: e,
                                    })?;
                                    std::fs::write(&target, &done.bytes).map_err(|e| {
                                        Error::Io {
                                            path: target.clone(),
                                            source: e,
                                        }
                                    })?;
                                    blobs_done += 1;
                                    println!(
                                        "blob {} ({} B, {}) → {}",
                                        done.name,
                                        done.bytes.len(),
                                        done.kind,
                                        target.display()
                                    );
                                }
                            }
                            Err(e) => eprintln!("blob chunk rejected: {e}"),
                        }
                    }
                }
            }

            for (blob_id, assembler) in &assemblers {
                eprintln!(
                    "blob {} incomplete: {}/{} chunks (rerun inbox when the rest arrive)",
                    hex::encode(&blob_id[..8]),
                    assembler.have(),
                    assembler.total()
                );
            }

            hive.save(&home)?;
            if joined > 0 {
                println!("{joined} cell key(s) installed");
            }
            if blobs_done > 0 {
                println!("{blobs_done} blob(s) written to {}", save_dir.display());
            }
            println!("{opened}/{} opened", envelopes.len());
        }

        Command::Relay { command } => match command {
            RelayCommand::Serve { bind, cap } => {
                let server = RelayServer::start(&bind, cap)?;
                println!(
                    "relay listening on {} (memory only, no disk, no logs)",
                    server.addr()
                );
                println!("queue cap: {cap} frames, oldest dropped first");
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(3600));
                }
            }
        },

        Command::Seal { label } => {
            let identity = match label {
                Some(label) => home.load(&label)?.0,
                None => home.active()?.0,
            };
            println!("{}", hex::encode(identity.seal));
        }

        Command::Swarm { command } => run_swarm(&home, command)?,
        Command::Group { command } => run_group(&home, command)?,
    }

    Ok(())
}

fn run_swarm(home: &Home, command: SwarmCommand) -> Result<()> {
    match command {
        SwarmCommand::Show => {
            let hive = Beehive::load(home)?;
            if hive.peers.is_empty() && hive.cells.is_empty() {
                println!("the hive is empty — `arnauth trust <card>` to learn a peer");
                return Ok(());
            }

            let mut peers: Vec<_> = hive.peers.iter().collect();
            peers.sort_by(|a, b| {
                b.weight
                    .cmp(&a.weight)
                    .then(a.card.label.cmp(&b.card.label))
            });

            println!("peers ({}):", peers.len());
            for peer in peers {
                println!(
                    "  {:<32} w={:<4} sent={:<4} heard={:<4} {}",
                    peer.card.label,
                    peer.weight,
                    peer.sent,
                    peer.heard,
                    if peer.claimed { "claimed" } else { "attested" }
                );
            }

            if hive.cells.is_empty() {
                return Ok(());
            }
            println!("cells ({}):", hive.cells.len());
            for cell in &hive.cells {
                println!(
                    "  {:<32} id={} members={} w={}",
                    cell.name,
                    hex::encode(cell.id),
                    cell.members.len(),
                    cell.weight
                );
                for member in &cell.members {
                    let label = hive
                        .peer(member)
                        .map(|peer| peer.card.label.clone())
                        .unwrap_or_else(|| hex::encode(&member[..8]));
                    println!("      {label}");
                }
            }
        }

        SwarmCommand::Share { out } => {
            let hive = Beehive::load(home)?;
            let delta = hive.share(now_ms())?;
            let json = serde_json::to_string_pretty(&delta).map_err(|e| Error::Codec {
                what: "delta",
                detail: e.to_string(),
            })?;

            match out {
                Some(path) => {
                    std::fs::write(&path, format!("{json}\n")).map_err(|e| Error::Io {
                        path: path.clone(),
                        source: e,
                    })?;
                    println!("shared {} card(s) -> {}", delta.cards.len(), path.display());
                }
                None => println!("{json}"),
            }
        }

        SwarmCommand::Absorb { path } => {
            let raw = std::fs::read_to_string(&path).map_err(|e| Error::Io {
                path: path.clone(),
                source: e,
            })?;
            let delta: SwarmDelta = serde_json::from_str(&raw).map_err(|e| Error::Codec {
                what: "delta",
                detail: e.to_string(),
            })?;

            let mut hive = Beehive::load(home)?;
            let learned = hive.absorb(&delta, now_ms())?;
            hive.save(home)?;
            println!("absorbed {learned} new peer(s)");
        }

        SwarmCommand::Forget { half_life_days } => {
            let mut hive = Beehive::load(home)?;
            let before = hive.peers.len();
            let decay = Decay {
                half_life_ms: half_life_days.max(1) * DAY_MS,
                ..Decay::default()
            };
            hive.forget(now_ms(), decay);
            hive.save(home)?;
            println!(
                "forgot: {before} -> {} peer(s), {} dropped",
                hive.peers.len(),
                before.saturating_sub(hive.peers.len())
            );
        }

        SwarmCommand::Receipt => {
            let hive = Beehive::load(home)?;
            let receipt = hive.consolidate()?;
            println!("peers  {}", receipt.peers);
            println!("cells  {}", receipt.cells);
            println!("ratio  {}", receipt.ratio());
            println!("wire   {}", receipt.wire_hex());
        }
    }
    Ok(())
}

fn run_group(home: &Home, command: GroupCommand) -> Result<()> {
    match command {
        GroupCommand::New { name } => {
            let mut hive = Beehive::load(home)?;
            let cell = hive.new_cell(&name, now_ms())?;
            hive.save(home)?;
            println!("{} id={}", cell.name, hex::encode(cell.id));
            println!("  the key never leaves this store except through `group invite`");
        }

        GroupCommand::Add { cell, member } => {
            let mut hive = Beehive::load(home)?;
            let peer = hive
                .peer_by_label(&member)
                .ok_or_else(|| Error::NotFound(member.clone()))?
                .card
                .clone();
            hive.add_member(&cell, peer.subject, now_ms())?;
            hive.save(home)?;
            println!(
                "{} added to {}",
                peer.label,
                cell.trim().to_ascii_lowercase()
            );
            println!("  run `group invite` to hand them the key");
        }

        GroupCommand::Invite { cell, member, from } => {
            let (identity, keys) = match from {
                Some(label) => home.load(&label)?,
                None => home.active()?,
            };
            let mut hive = Beehive::load(home)?;
            let target = hive
                .peer_by_label(&member)
                .ok_or_else(|| Error::NotFound(member.clone()))?
                .card
                .clone();
            let cell_value = hive
                .cell(&cell)
                .ok_or_else(|| Error::NotFound(cell.clone()))?
                .clone();

            group::invite(
                &cell_value,
                &identity,
                &keys,
                target.dh_public,
                &Spool::new(home),
            )?;
            hive.add_member(&cell, target.subject, now_ms())?;
            hive.save(home)?;
            println!("key for {} handed to {}", cell_value.name, target.label);
        }

        GroupCommand::Send { cell, body, from } => {
            let (identity, keys) = match from {
                Some(label) => home.load(&label)?,
                None => home.active()?,
            };
            let hive = Beehive::load(home)?;
            let cell_value = hive
                .cell(&cell)
                .ok_or_else(|| Error::NotFound(cell.clone()))?
                .clone();

            let queued = group::send(
                &cell_value,
                &identity,
                &keys,
                body.as_bytes(),
                &hive,
                &Spool::new(home),
            )?;
            if queued == 0 {
                println!(
                    "nothing queued — {} has no members with a known key",
                    cell_value.name
                );
            } else {
                println!("sealed once for {queued} member(s) of {}", cell_value.name);
            }
        }

        GroupCommand::List => {
            let hive = Beehive::load(home)?;
            if hive.cells.is_empty() {
                println!("no cells — `arnauth group new <name>`");
                return Ok(());
            }
            for cell in &hive.cells {
                println!(
                    "{:<32} id={} members={}",
                    cell.name,
                    hex::encode(cell.id),
                    cell.members.len()
                );
            }
        }
    }
    Ok(())
}

/// Reconstruct the sender's card from an envelope. The key is proven by the
/// signature; the label is only claimed, so it is learned as `claimed`.
fn claimed_card(message: &OpenedEnvelope) -> ContactCard {
    let (label, kind) = parse_label(&message.from_label).unwrap_or_else(|_| {
        (
            format!("unknown-{}", hex::encode(&message.from_verifying_key[..4])),
            IdentityKind::Name,
        )
    });
    ContactCard {
        subject: subject_for(&label),
        label,
        kind,
        verifying_key: message.from_verifying_key,
        dh_public: [0u8; 32],
        pq: None,
    }
}

fn print_identity(identity: &Identity) {
    println!("{}", identity.label);
    println!("  kind    {}", identity.kind);
    println!("  subject {}", hex::encode(identity.subject));
    println!("  verify  {}", hex::encode(identity.verifying_key));
    println!("  dh      {}", hex::encode(identity.dh_public));
    println!("  seal    {}", hex::encode(identity.seal));
    println!("  created {}", identity.created_seconds());
}

fn blob_payload(chunk: &BlobChunk) -> Vec<u8> {
    Payload::Blob {
        blob_id: chunk.blob_id,
        index: chunk.index,
        total: chunk.total,
        hash: chunk.hash,
        name: chunk.name.clone(),
        kind: chunk.kind.clone(),
        data: chunk.data.clone(),
    }
    .encode()
}

fn parse_addr(raw: &str) -> Result<std::net::SocketAddr> {
    raw.parse().map_err(|_| Error::Malformed {
        what: "relay address",
        detail: format!("{raw:?} is not host:port"),
    })
}

/// Never overwrite a received file; `photo.jpg` becomes `photo-2.jpg`.
fn unique_path(dir: &std::path::Path, name: &str) -> Result<PathBuf> {
    let mut candidate = dir.join(name);
    if !candidate.exists() {
        return Ok(candidate);
    }

    let path = std::path::Path::new(name);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("blob");
    let ext = path.extension().and_then(|e| e.to_str());

    for n in 2..1000 {
        let file = match ext {
            Some(ext) => format!("{stem}-{n}.{ext}"),
            None => format!("{stem}-{n}"),
        };
        candidate = dir.join(file);
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(Error::Malformed {
        what: "download",
        detail: format!("too many files named {name} already"),
    })
}

fn guess_mime(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    match lower.rsplit('.').next() {
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        Some("pdf") => "application/pdf",
        Some("txt") | Some("md") => "text/plain",
        Some("json") => "application/json",
        Some("mp3") => "audio/mpeg",
        Some("wav") => "audio/wav",
        Some("mp4") => "video/mp4",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
}
