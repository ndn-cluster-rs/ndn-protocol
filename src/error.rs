use thiserror::Error;

pub type Result<T> = std::result::Result<T, NdnError>;

#[derive(Error, Debug)]
pub enum NdnError {
    #[error("Parse error")]
    ParseError,
    #[error("Failed to verify")]
    VerifyError(VerifyError),
}

impl From<url::ParseError> for NdnError {
    fn from(_value: url::ParseError) -> Self {
        NdnError::ParseError
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
