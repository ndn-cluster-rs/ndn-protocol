//! NDN certificates: [`Certificate`], a signed [`Data`] packet carrying a
//! public key, and [`SafeBag`], the format NDN tools export a certificate
//! and its matching private key in together.
//!
//! [`RsaCertificate`] pairs a [`Certificate`] with the RSA key material
//! needed to actually sign and verify with it -- see
//! [`RsaCertificate::from_safebag`] to load one from a `.safebag`/`.ndnkeys`
//! file exported by ndn-cxx tools.

use std::path::Path;

use base64::Engine;
use bytes::Bytes;
use ndn_tlv::{Tlv, TlvDecode, TlvEncode};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    RsaPrivateKey, RsaPublicKey,
};

use crate::{error::NdnError, Data, KeyLocator, Name, SignatureInfo};

/// The on-disk format NDN tools (e.g. `ndnsec`) export a certificate and
/// its private key together in, encrypted with a password.
#[derive(Tlv, Clone, Hash, Debug)]
#[tlv(128)]
pub struct SafeBag {
    /// The certificate, as a signed [`Data`] packet.
    pub certificate: Data<Bytes>,
    /// The private key, encrypted with the export password.
    pub encrypted_key: EncryptedKey,
}

/// The encrypted private key portion of a [`SafeBag`].
#[derive(Tlv, Clone, Hash, Debug)]
#[tlv(129)]
pub struct EncryptedKey {
    /// The encrypted key data.
    pub data: Bytes,
}

/// An NDN certificate: a [`Data`] packet whose content is a public key,
/// signed by an issuer.
#[derive(Clone, Debug, Hash)]
pub struct Certificate(pub Data<Bytes>);

/// Implemented by types that can produce the [`Certificate`] backing them,
/// e.g. [`RsaCertificate`].
pub trait ToCertificate {
    /// Returns the certificate.
    fn to_certificate(&self) -> Certificate;
}

/// A [`Certificate`] together with the RSA key material needed to sign and
/// verify with it. The private key is only present if it was loaded, e.g.
/// via [`RsaCertificate::from_safebag`] or [`RsaCertificate::with_private`].
#[derive(Clone, Debug, Hash)]
pub struct RsaCertificate {
    cert: Certificate,
    public_key: RsaPublicKey,
    private_key: Option<RsaPrivateKey>,
}

impl RsaCertificate {
    /// Wraps `cert` as an `RsaCertificate` with no private key, by
    /// extracting its public key from the certificate's content.
    ///
    /// Returns `None` if the certificate's content isn't a valid RSA
    /// public key.
    pub fn new(cert: Certificate) -> Option<Self> {
        let key = RsaPublicKey::from_public_key_der(&cert.0.content()?).ok()?;
        Some(Self {
            cert,
            public_key: key,
            private_key: None,
        })
    }

    /// Wraps `cert` as an `RsaCertificate`, together with its matching
    /// private key.
    ///
    /// Returns `None` if the certificate's content isn't a valid RSA
    /// public key.
    pub fn with_private(cert: Certificate, private_key: RsaPrivateKey) -> Option<Self> {
        let key = RsaPublicKey::from_public_key_der(&cert.0.content()?).ok()?;
        Some(Self {
            cert,
            public_key: key,
            private_key: Some(private_key),
        })
    }

    /// Decrypts the private key in `bag` with `password` and pairs it with
    /// the certificate it came with.
    ///
    /// Returns `None` if the password is wrong or the key/certificate data
    /// is malformed.
    pub fn from_safebag<P>(bag: SafeBag, password: P) -> Option<Self>
    where
        P: AsRef<[u8]>,
    {
        let key =
            RsaPrivateKey::from_pkcs8_encrypted_der(&bag.encrypted_key.data, password).ok()?;
        Self::with_private(Certificate(bag.certificate), key)
    }

    /// The certificate's name.
    pub fn name(&self) -> &Name {
        self.cert.name()
    }

    /// The RSA public key.
    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    /// The RSA private key, if one was loaded.
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
    /// Reads and decodes a base64-encoded `.safebag` file, e.g. one
    /// exported by `ndnsec export`.
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
    /// Reads and decodes a base64-encoded certificate file (just the
    /// certificate, without an accompanying private key).
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

    /// The certificate's name, of the form `/<identity>/KEY/<key-id>/<issuer-id>/<version>`.
    pub fn name(&self) -> &Name {
        self.0.name()
    }

    /// The identity this certificate belongs to: its name with the
    /// trailing `KEY/<key-id>/<issuer-id>/<version>` components removed.
    pub fn identity(&self) -> Name {
        let mut name = self.name().clone();
        name.components.pop();
        name.components.pop();
        name.components.pop();
        name.components.pop();
        name
    }

    /// A [`KeyLocator`] pointing at this certificate by name, for use in a
    /// [`SignatureInfo`]/`InterestSignatureInfo`.
    pub fn name_locator(&self) -> KeyLocator {
        KeyLocator::new(crate::signature::KeyLocatorData::Name(self.name().clone()))
    }

    /// The certificate as the [`Data`] packet it's backed by.
    pub fn as_data(&self) -> &Data<Bytes> {
        &self.0
    }

    /// The signature info of the Data packet backing this certificate,
    /// i.e. how the issuer signed it.
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
