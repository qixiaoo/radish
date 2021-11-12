use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    InvalidVersion,
    InvalidHeaderLen,
    InvalidTotalLen,
    InvalidChecksum,
    InvalidOptionLen,
    NonFragmentablePacket,
    TryAgainLater,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidVersion => write!(f, "invalid version"),
            Error::InvalidHeaderLen => write!(f, "invalid header length"),
            Error::InvalidTotalLen => write!(f, "invalid total length"),
            Error::InvalidChecksum => write!(f, "invalid checksum"),
            Error::InvalidOptionLen => write!(f, "invalid option length"),
            Error::NonFragmentablePacket => write!(f, "non-fragmentable packet"),
            Error::TryAgainLater => write!(f, "try again later"),
        }
    }
}

impl std::error::Error for Error {}
