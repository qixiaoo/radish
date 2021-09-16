use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    InvalidVersion,
    InvalidHeaderLen,
    InvalidTotalLen,
    InvalidOptionLen,
    NonFragmentablePacket,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidVersion => write!(f, "invalid version"),
            Error::InvalidHeaderLen => write!(f, "invalid header length"),
            Error::InvalidTotalLen => write!(f, "invalid total length"),
            Error::InvalidOptionLen => write!(f, "invalid option length"),
            Error::NonFragmentablePacket => write!(f, "non-fragmentable packet"),
        }
    }
}

impl std::error::Error for Error {}
