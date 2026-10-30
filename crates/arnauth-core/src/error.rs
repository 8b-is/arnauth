use std::path::PathBuf;

/// Everything this crate can refuse to do.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("identity label is not valid: {0}")]
    InvalidLabel(String),

    #[error("identity not found: {0}")]
    NotFound(String),

    #[error("identity already exists: {0}")]
    AlreadyExists(String),

    #[error("identity seal does not match its contents")]
    SealMismatch,

    #[error("keys are missing for identity {0}")]
    MissingKeys(String),

    #[error("envelope is addressed to a different identity")]
    WrongRecipient,

    #[error("envelope signature is not valid")]
    BadSignature,

    #[error("envelope could not be opened: {0}")]
    Decrypt(String),

    #[error("malformed {what}: {detail}")]
    Malformed { what: &'static str, detail: String },

    #[error("no active identity in {0}")]
    NoActiveIdentity(PathBuf),

    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not serialize {what}: {detail}")]
    Codec { what: &'static str, detail: String },
}

impl Error {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
