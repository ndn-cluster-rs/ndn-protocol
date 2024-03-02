use bytes::Bytes;
use ndn_tlv::Tlv;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    RsaPrivateKey, RsaPublicKey,
};

use crate::{signature::KeyLocatorData, Data, KeyLocator, Name};

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

pub trait Certificate {
    type PublicKey;
    type PrivateKey;

    fn locator(&self) -> Option<KeyLocator>;

    fn public_key(&self) -> &Self::PublicKey;

    fn private_key(&self) -> Option<&Self::PrivateKey>;
}

impl Certificate for () {
    type PublicKey = ();
    type PrivateKey = ();

    fn locator(&self) -> Option<KeyLocator> {
        None
    }

    fn public_key(&self) -> &Self::PublicKey {
        &()
    }

    fn private_key(&self) -> Option<&Self::PrivateKey> {
        Some(&())
    }
}

#[derive(Clone, Debug, Hash)]
pub struct RsaCertificate {
    public_key: RsaPublicKey,
    private_key: Option<RsaPrivateKey>,
    name: Name,
}

impl RsaCertificate {
    pub fn new(name: Name, public_key: RsaPublicKey) -> Self {
        Self {
            name,
            public_key,
            private_key: None,
        }
    }

    pub fn with_private(name: Name, private_key: RsaPrivateKey) -> Self {
        Self {
            name,
            public_key: private_key.to_public_key(),
            private_key: Some(private_key),
        }
    }
}

impl Certificate for RsaCertificate {
    type PublicKey = RsaPublicKey;

    type PrivateKey = RsaPrivateKey;

    fn locator(&self) -> Option<KeyLocator> {
        Some(KeyLocator::new(KeyLocatorData::Name(self.name.clone())))
    }

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn private_key(&self) -> Option<&Self::PrivateKey> {
        self.private_key.as_ref()
    }
}

impl RsaCertificate {
    pub fn from_safebag<P>(bag: SafeBag, password: P) -> Option<Self>
    where
        P: AsRef<[u8]>,
    {
        let name = bag.certificate.name().clone();
        let key =
            RsaPrivateKey::from_pkcs8_encrypted_der(&bag.encrypted_key.data, password).ok()?;
        Some(Self::with_private(name, key))
    }

    pub fn from_data(data: Data<Bytes>) -> Option<Self> {
        let name = data.name().clone();
        let key = RsaPublicKey::from_public_key_der(&data.content()?).ok()?;
        Some(Self::new(name, key))
    }
}
