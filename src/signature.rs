use bytes::Bytes;
use derive_more::{AsMut, AsRef, Constructor, Display, From, Into};
use ndn_tlv::{NonNegativeInteger, Tlv, VarNum};

use rand::SeedableRng;
use rsa::{
    pkcs1v15::{Signature, SigningKey},
    signature::{RandomizedSigner, SignatureEncoding},
    Pkcs1v15Sign,
};
use sha2::{Digest, Sha256};

use crate::{Certificate, Name, RsaCertificate};

#[derive(
    Debug, Tlv, PartialEq, Eq, Clone, Hash, From, Into, AsRef, AsMut, Display, Constructor,
)]
#[tlv(27)]
pub struct SignatureType {
    signature_type: VarNum,
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, From, Into, AsRef, AsMut, Constructor)]
#[tlv(29)]
pub struct KeyDigest {
    data: Bytes,
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash)]
pub enum KeyLocatorData {
    Name(Name),
    KeyDigest(KeyDigest),
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, AsRef, AsMut, Constructor, From, Into)]
#[tlv(28)]
pub struct KeyLocator {
    locator: KeyLocatorData,
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, Constructor)]
#[tlv(22)]
pub struct SignatureInfo {
    signature_type: SignatureType,
    key_locator: Option<KeyLocator>,
}

impl SignatureInfo {
    pub fn signature_type(&self) -> VarNum {
        self.signature_type.signature_type
    }

    pub fn key_locator(&self) -> Option<&KeyLocator> {
        self.key_locator.as_ref()
    }
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, AsRef, AsMut, Constructor, From, Into)]
#[tlv(23)]
pub struct SignatureValue {
    data: Bytes,
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, AsRef, AsMut, Constructor, From, Into)]
#[tlv(38)]
pub struct SignatureNonce {
    data: Bytes,
}

#[derive(
    Debug,
    Tlv,
    PartialEq,
    Eq,
    Clone,
    Hash,
    AsRef,
    AsMut,
    Constructor,
    From,
    Into,
    Display,
    PartialOrd,
    Ord,
)]
#[tlv(40)]
pub struct SignatureTime {
    data: NonNegativeInteger,
}

#[derive(
    Debug,
    Tlv,
    PartialEq,
    Eq,
    Clone,
    Hash,
    From,
    Into,
    AsRef,
    AsMut,
    Constructor,
    PartialOrd,
    Ord,
    Display,
)]
#[tlv(42)]
pub struct SignatureSeqNum {
    data: NonNegativeInteger,
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, Constructor)]
#[tlv(44)]
pub struct InterestSignatureInfo {
    pub(crate) signature_type: SignatureType,
    pub(crate) key_locator: Option<KeyLocator>,
    pub(crate) nonce: Option<SignatureNonce>,
    pub(crate) time: Option<SignatureTime>,
    pub(crate) seq_num: Option<SignatureSeqNum>,
}

impl InterestSignatureInfo {
    pub fn signature_type(&self) -> VarNum {
        self.signature_type.signature_type
    }

    pub fn key_locator(&self) -> Option<&KeyLocatorData> {
        self.key_locator.as_ref().map(|x| &x.locator)
    }

    pub fn nonce(&self) -> Option<&Bytes> {
        self.nonce.as_ref().map(|x| &x.data)
    }

    pub fn time(&self) -> Option<NonNegativeInteger> {
        self.time.as_ref().map(|x| x.data)
    }

    pub fn seq_num(&self) -> Option<NonNegativeInteger> {
        self.seq_num.as_ref().map(|x| x.data)
    }
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, From, Into, AsRef, AsMut, Constructor)]
#[tlv(46)]
pub struct InterestSignatureValue {
    data: Bytes,
}

pub trait SignMethod {
    const SIGNATURE_TYPE: u64;
    type Certificate: Certificate;

    fn next_seq_num(&mut self) -> u64;

    fn certificate(&self) -> &Self::Certificate;

    fn sign(&self, data: &[u8]) -> Bytes;

    fn verify(&self, data: &[u8], cert: Self::Certificate, signature: &[u8]) -> bool;

    fn time(&self) -> SignatureTime {
        SignatureTime {
            data: NonNegativeInteger::from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            ),
        }
    }
}

impl<T: SignMethod> SignMethod for &mut T {
    const SIGNATURE_TYPE: u64 = T::SIGNATURE_TYPE;

    type Certificate = T::Certificate;

    fn next_seq_num(&mut self) -> u64 {
        (**self).next_seq_num()
    }

    fn certificate(&self) -> &Self::Certificate {
        (**self).certificate()
    }

    fn sign(&self, data: &[u8]) -> Bytes {
        (**self).sign(data)
    }

    fn verify(&self, data: &[u8], cert: Self::Certificate, signature: &[u8]) -> bool {
        (**self).verify(data, cert, signature)
    }
}

#[derive(Clone, Debug)]
pub struct DigestSha256 {
    seq_num: u64,
}

impl DigestSha256 {
    pub const fn new() -> Self {
        DigestSha256 { seq_num: 0 }
    }
}

impl SignMethod for DigestSha256 {
    const SIGNATURE_TYPE: u64 = 0;
    type Certificate = ();

    fn next_seq_num(&mut self) -> u64 {
        let seq_num = self.seq_num;
        self.seq_num += 1;
        seq_num
    }

    fn sign(&self, data: &[u8]) -> Bytes {
        let mut hasher = Sha256::new();
        hasher.update(data);

        Bytes::copy_from_slice(&hasher.finalize())
    }

    fn verify(&self, data: &[u8], _: Self::Certificate, signature: &[u8]) -> bool {
        let hashed = self.sign(data);
        hashed == signature
    }

    fn certificate(&self) -> &Self::Certificate {
        &()
    }
}

#[derive(Clone, Debug)]
pub struct SignatureSha256WithRsa {
    cert: RsaCertificate,
    seq_num: u64,
}

impl SignatureSha256WithRsa {
    pub const fn new(cert: RsaCertificate) -> Self {
        Self { cert, seq_num: 0 }
    }
}

impl SignMethod for SignatureSha256WithRsa {
    const SIGNATURE_TYPE: u64 = 1;

    type Certificate = RsaCertificate;

    fn next_seq_num(&mut self) -> u64 {
        let seq_num = self.seq_num;
        self.seq_num += 1;
        seq_num
    }

    fn sign(&self, data: &[u8]) -> Bytes {
        let private_key = self.cert.private_key().unwrap(); // TODO: Error handling
        let signing_key = SigningKey::<Sha256>::new(private_key.clone());
        let mut rng = rand::rngs::StdRng::from_entropy();

        let output: Signature = signing_key.sign_with_rng(&mut rng, &data);
        let outputvec = output.to_vec();
        Bytes::from(outputvec)
    }

    fn verify(&self, data: &[u8], cert: Self::Certificate, signature: &[u8]) -> bool {
        let mut hasher: Sha256 = Sha256::new();
        hasher.update(data);
        let hashed = hasher.finalize();

        cert.public_key()
            .verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, &signature)
            .is_ok()
    }

    fn certificate(&self) -> &Self::Certificate {
        &self.cert
    }
}
