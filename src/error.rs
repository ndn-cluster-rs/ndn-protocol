use thiserror::Error;

pub type Result<T> = std::result::Result<T, NdnError>;

#[derive(Error, Debug)]
pub enum NdnError {
    #[error("Parse error")]
    ParseError,
}

impl From<url::ParseError> for NdnError {
    fn from(value: url::ParseError) -> Self {
        NdnError::ParseError
    }
}
