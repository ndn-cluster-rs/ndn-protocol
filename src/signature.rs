use bytes::{Buf, Bytes};
use ndn_tlv::{Tlv, TlvEncode, VarNum};

use sha2::{Digest, Sha256};

use crate::Name;

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
    pub(crate) data: VarNum,
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

    fn locator(&self) -> Option<KeyLocator>;

    fn next_seq_num(&mut self) -> u64;

    fn sign(&self, data: Bytes) -> Bytes;

    fn time(&self) -> SignatureTime {
        SignatureTime {
            data: VarNum::from(
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

    fn locator(&self) -> Option<KeyLocator> {
        None
    }

    fn next_seq_num(&mut self) -> u64 {
        let seq_num = self.seq_num;
        self.seq_num += 1;
        seq_num
    }

    fn sign(&self, data: Bytes) -> Bytes {
        let mut hasher = Sha256::new();
        hasher.update(data);

        Bytes::copy_from_slice(&hasher.finalize())
    }
}