use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    InvalidDataOffset,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidDataOffset => write!(f, "invalid data offset"),
        }
    }
}

impl std::error::Error for Error {}
