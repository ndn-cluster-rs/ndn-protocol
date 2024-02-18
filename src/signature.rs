use bytes::Bytes;
use ndn_tlv::{NonNegativeInteger, Tlv, TlvEncode, VarNum};

use rand::SeedableRng;
use rsa::{
    pkcs1v15::{Signature, SigningKey},
    signature::{RandomizedSigner, SignatureEncoding},
    Pkcs1v15Sign,
};
use sha2::{Digest, Sha256};

use crate::{Certificate, Name, RsaCertificate};

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(27)]
pub struct SignatureType {
    pub(crate) signature_type: VarNum,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(29)]
pub struct KeyDigest {
    pub(crate) data: Bytes,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
pub enum KeyLocatorData {
    Name(Name),
    KeyDigest(KeyDigest),
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(28)]
pub struct KeyLocator {
    pub(crate) locator: KeyLocatorData,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(22)]
pub struct SignatureInfo {
    pub(crate) signature_type: SignatureType,
    pub(crate) key_locator: Option<KeyLocator>,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(23)]
pub struct SignatureValue {
    pub(crate) data: Bytes,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(38)]
pub struct SignatureNonce {
    pub(crate) data: Bytes,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(40)]
pub struct SignatureTime {
    pub(crate) data: NonNegativeInteger,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(42)]
pub struct SignatureSeqNum {
    pub(crate) data: VarNum,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(44)]
pub struct InterestSignatureInfo {
    pub(crate) signature_type: SignatureType,
    pub(crate) key_locator: Option<KeyLocator>,
    pub(crate) nonce: Option<SignatureNonce>,
    pub(crate) time: Option<SignatureTime>,
    pub(crate) seq_num: Option<SignatureSeqNum>,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(46)]
pub struct InterestSignatureValue {
    pub(crate) data: Bytes,
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

pub struct DigestSha256 {
    seq_num: u64,
}

impl DigestSha256 {
    pub fn new() -> Self {
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

pub struct SignatureSha256WithRsa {
    cert: RsaCertificate,
    seq_num: u64,
}

impl SignatureSha256WithRsa {
    pub fn new(cert: RsaCertificate) -> Self {
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
