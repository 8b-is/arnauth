//! Arnauth core: identities sealed with wupz, keys from one seed, end-to-end
//! envelopes, and a local sealed store.
//!
//! The pieces are deliberately small. There is no network transport here and no
//! notification substrate: `transport` is a local spool you can point a real
//! carrier at, and everything else is offline and testable.

pub mod api;
pub mod beehive;
pub mod contacts;
pub mod envelope;
pub mod error;
pub mod group;
pub mod hexcodec;
pub mod identity;
pub mod keys;
pub mod media;
pub mod payload;
pub mod pq;
pub mod relay;
pub mod seal;
pub mod store;
pub mod transport;

pub use api::{Event, Webhook, Webhooks};
pub use beehive::{Beehive, Cell, Peer};
pub use contacts::{ContactCard, Contacts};
pub use envelope::{Envelope, OpenedEnvelope};
pub use error::{Error, Result};
pub use identity::{Identity, IdentityKind};
pub use payload::Payload;
pub use store::Home;

/// Protocol version for every row, frame, and envelope this crate writes.
pub const PROTOCOL_VERSION: u8 = 1;
