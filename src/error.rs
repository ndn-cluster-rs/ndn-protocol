//! Error types returned by this crate's fallible operations.

use ndn_tlv::TlvError;
use thiserror::Error;

/// The `Result` type used throughout this crate, with the error type fixed to [`NdnError`].
pub type Result<T> = std::result::Result<T, NdnError>;

/// The general-purpose error type for this crate.
#[derive(Error, Debug)]
pub enum NdnError {
    /// A [`Name`](crate::Name) URI could not be parsed.
    #[error("Parse error")]
    ParseError,
    /// Signature or parameter digest verification failed.
    #[error("Failed to verify")]
    VerifyError(VerifyError),
    /// The underlying TLV data was malformed.
    #[error("TLV Error: {0}")]
    TlvError(TlvError),
    /// A catch-all for errors that don't fit the other variants.
    #[error("{0}")]
    GenericError(String),
    /// An I/O operation failed, e.g. while reading a certificate file.
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

/// Errors that can occur while signing an [`Interest`](crate::Interest).
#[derive(Error, Debug)]
pub enum SignError {
    /// The interest has no application parameters to sign; set some before
    /// calling `sign` (see
    /// [`Interest::set_application_parameters`](crate::Interest::set_application_parameters)).
    #[error("No application parameters present")]
    MissingApplicationParameters,
}

/// Errors that can occur while verifying a signed
/// [`Interest`](crate::Interest) or [`Data`](crate::Data) packet.
#[derive(Error, Debug)]
pub enum VerifyError {
    /// The name's `ParametersSha256DigestComponent` doesn't match the
    /// signed application parameters.
    #[error("The parameter digest is invalid")]
    InvalidParameterDigest,
    /// The signature doesn't match the signed content.
    #[error("The signature is invalid")]
    InvalidSignature,
    /// The packet is signed but carries no signature info.
    #[error("The interest has no signature info")]
    MissingSignatureInfo,
    /// The packet is signed but has no application parameters to include
    /// in the signature.
    #[error("The signed interest has no application parameters")]
    MissingApplicationParameters,
    /// The signature's type isn't recognized by the verifier being used.
    #[error("Signed with an unknown sign method")]
    UnknownSignMethod,
}
