use ndn_tlv::TlvError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, NdnError>;

#[derive(Error, Debug)]
pub enum NdnError {
    #[error("Parse error")]
    ParseError,
    #[error("Failed to verify")]
    VerifyError(VerifyError),
    #[error("TLV Error: {0}")]
    TlvError(TlvError),
    #[error("{0}")]
    GenericError(String),
    #[error("IO Error: {0}")]
    IOError(std::io::Error),
}

impl From<url::ParseError> for NdnError {
    fn from(_value: url::ParseError) -> Self {
        NdnError::ParseError
    }
}

impl From<TlvError> for NdnError {
    fn from(value: TlvError) -> Self {
        NdnError::TlvError(value)
    }
}

impl From<std::io::Error> for NdnError {
    fn from(value: std::io::Error) -> Self {
        NdnError::IOError(value)
    }
}

#[derive(Error, Debug)]
pub enum SignError {
    #[error("No application parameters present")]
    MissingApplicationParameters,
}

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("The parameter digest is invalid")]
    InvalidParameterDigest,
    #[error("The signature is invalid")]
    InvalidSignature,
    #[error("The interest has no signature info")]
    MissingSignatureInfo,
    #[error("The signed interest has no application parameters")]
    MissingApplicationParameters,
    #[error("Signed with an unknown sign method")]
    UnknownSignMethod,
}
