use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    NameTooLong,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NameTooLong => write!(f, "device name too long"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
