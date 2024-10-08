use std::path::Path;

use base64::Engine;
use bytes::Bytes;
use ndn_tlv::{Tlv, TlvDecode, TlvEncode};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    RsaPrivateKey, RsaPublicKey,
};

use crate::{error::NdnError, Data, KeyLocator, Name, SignatureInfo};

#[derive(Tlv, Clone, Hash, Debug)]
#[tlv(128)]
pub struct SafeBag {
    pub certificate: Data<Bytes>,
    pub encrypted_key: EncryptedKey,
}

#[derive(Tlv, Clone, Hash, Debug)]
#[tlv(129)]
pub struct EncryptedKey {
    pub data: Bytes,
}

#[derive(Clone, Debug, Hash)]
pub struct Certificate(pub Data<Bytes>);

pub trait ToCertificate {
    fn to_certificate(&self) -> Certificate;
}

#[derive(Clone, Debug, Hash)]
pub struct RsaCertificate {
    cert: Certificate,
    public_key: RsaPublicKey,
    private_key: Option<RsaPrivateKey>,
}

impl RsaCertificate {
    pub fn new(cert: Certificate) -> Option<Self> {
        let key = RsaPublicKey::from_public_key_der(&cert.0.content()?).ok()?;
        Some(Self {
            cert,
            public_key: key,
            private_key: None,
        })
    }

    pub fn with_private(cert: Certificate, private_key: RsaPrivateKey) -> Option<Self> {
        let key = RsaPublicKey::from_public_key_der(&cert.0.content()?).ok()?;
        Some(Self {
            cert,
            public_key: key,
            private_key: Some(private_key),
        })
    }

    pub fn from_safebag<P>(bag: SafeBag, password: P) -> Option<Self>
    where
        P: AsRef<[u8]>,
    {
        let key =
            RsaPrivateKey::from_pkcs8_encrypted_der(&bag.encrypted_key.data, password).ok()?;
        Self::with_private(Certificate(bag.certificate), key)
    }

    pub fn name(&self) -> &Name {
        self.cert.name()
    }

    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    pub fn private_key(&self) -> Option<&RsaPrivateKey> {
        self.private_key.as_ref()
    }
}

impl ToCertificate for RsaCertificate {
    fn to_certificate(&self) -> Certificate {
        self.cert.clone()
    }
}

impl SafeBag {
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, NdnError> {
        let mut file_content = std::fs::read(path)?;
        file_content.retain(|x| *x != b'\n' && *x != b'\r');
        let safebag_data = base64::engine::general_purpose::STANDARD
            .decode(&file_content)
            .map_err(|_| {
                NdnError::GenericError("Could not base64-decode certificate".to_string())
            })?;
        Ok(SafeBag::decode(&mut Bytes::from(safebag_data))?)
    }
}

impl Certificate {
    pub fn load_file<P>(path: P) -> Result<Self, NdnError>
    where
        P: AsRef<Path>,
    {
        let mut file_content = std::fs::read(path)?;
        file_content.retain(|x| *x != b'\n' && *x != b'\r');
        let safebag_data = base64::engine::general_purpose::STANDARD
            .decode(&file_content)
            .map_err(|_| {
                NdnError::GenericError("Could not base64-decode certificate".to_string())
            })?;
        Ok(Self(Data::<Bytes>::decode(&mut Bytes::from(safebag_data))?))
    }

    pub fn name(&self) -> &Name {
        self.0.name()
    }

    pub fn identity(&self) -> Name {
        let mut name = self.name().clone();
        name.components.pop();
        name.components.pop();
        name.components.pop();
        name.components.pop();
        name
    }

    pub fn name_locator(&self) -> KeyLocator {
        KeyLocator::new(crate::signature::KeyLocatorData::Name(self.name().clone()))
    }

    pub fn as_data(&self) -> &Data<Bytes> {
        &self.0
    }

    pub fn signature_info(&self) -> Option<&SignatureInfo> {
        self.0.signature_info()
    }
}

impl TlvEncode for Certificate {
    fn encode(&self) -> Bytes {
        self.0.encode()
    }

    fn size(&self) -> usize {
        self.0.size()
    }
}

impl TlvDecode for Certificate {
    fn decode(bytes: &mut Bytes) -> ndn_tlv::Result<Self> {
        Data::<Bytes>::decode(bytes).map(Self)
    }
}
