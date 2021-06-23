use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    InvalidMessageType,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidMessageType => write!(f, "invalid message type"),
        }
    }
}

impl std::error::Error for Error {}
