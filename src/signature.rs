use std::io::Read;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_more::{AsMut, AsRef, Constructor, Display, From, Into};
use ndn_tlv::{NonNegativeInteger, Tlv, TlvDecode, TlvEncode, TlvError, VarNum};

use rand::SeedableRng;
use rsa::{
    pkcs1v15::{Signature, SigningKey},
    signature::{RandomizedSigner, SignatureEncoding},
    Pkcs1v15Sign,
};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, UtcOffset};

use crate::{
    certificate::ToCertificate, Certificate, ContentType, Data, MetaInfo, Name, RsaCertificate,
};

use self::signature_type::get_signature_type;

pub mod signature_type {
    use ndn_tlv::TlvEncode;

    use crate::Data;

    pub const DIGEST_SHA256: usize = 0;
    pub const SIGNATURE_SHA256_WITH_RSA: usize = 1;
    pub const SIGNATURE_SHA256_WITH_ECDSA: usize = 3;
    pub const SIGNATRUE_HMAC_WITH_SHA256: usize = 4;
    pub const SIGNATURE_ED25519: usize = 5;

    pub(super) fn get_signature_type<T: TlvEncode>(data: &Data<T>) -> Option<usize> {
        Some(
            data.signature_info()
                .as_ref()?
                .signature_type
                .signature_type
                .into(),
        )
    }

    pub(super) fn ensure_signature_type<T: TlvEncode>(data: &Data<T>, typ: usize) -> Option<()> {
        if get_signature_type(data)? != typ {
            return None;
        }
        Some(())
    }
}

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

impl KeyLocatorData {
    pub fn as_name(&self) -> Option<&Name> {
        if let Self::Name(v) = self {
            Some(v)
        } else {
            None
        }
    }

    pub fn as_key_digest(&self) -> Option<&KeyDigest> {
        if let Self::KeyDigest(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, AsRef, AsMut, Constructor, From, Into)]
#[tlv(28)]
pub struct KeyLocator {
    locator: KeyLocatorData,
}

impl KeyLocator {
    pub fn locator(&self) -> &KeyLocatorData {
        &self.locator
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Hash, Constructor)]
pub struct Timestamp {
    date: [u8; 8],
    time: [u8; 6],
}

impl From<OffsetDateTime> for Timestamp {
    fn from(value: OffsetDateTime) -> Self {
        let datetime = value.to_offset(UtcOffset::UTC);
        let date = format!(
            "{:02}{:02}{:04}",
            datetime.day(),
            datetime.month() as u8,
            datetime.year()
        );

        let mut date_buf = [0; 8];
        date_buf.copy_from_slice(&date.as_bytes());

        let time = format!(
            "{:02}{:02}{:02}",
            datetime.hour(),
            datetime.minute(),
            datetime.second()
        );

        let mut time_buf = [0; 6];
        time_buf.copy_from_slice(&time.as_bytes());
        Timestamp {
            date: date_buf,
            time: time_buf,
        }
    }
}

impl TlvEncode for Timestamp {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.size());
        bytes.put(&self.date[..]);
        bytes.put_u8(b'T');
        bytes.put(&self.time[..]);
        bytes.freeze()
    }

    fn size(&self) -> usize {
        15
    }
}

impl TlvDecode for Timestamp {
    fn decode(bytes: &mut Bytes) -> ndn_tlv::Result<Self> {
        if bytes.remaining() < 15 {
            return Err(TlvError::UnexpectedEndOfStream);
        }
        let mut date = [0; 8];
        let mut t = [0];
        let mut time = [0; 6];

        let mut reader = bytes.reader();
        reader
            .read_exact(&mut date)
            .map_err(|_| TlvError::FormatError)?;
        reader
            .read_exact(&mut t)
            .map_err(|_| TlvError::FormatError)?;
        reader
            .read_exact(&mut time)
            .map_err(|_| TlvError::FormatError)?;

        Ok(Self { date, time })
    }
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, Constructor)]
#[tlv(254)]
pub struct NotBefore {
    pub not_before: Timestamp,
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, Constructor)]
#[tlv(255)]
pub struct NotAfter {
    pub not_after: Timestamp,
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, Constructor)]
#[tlv(253)]
pub struct ValidityPeriod {
    pub not_before: NotBefore,
    pub not_after: NotAfter,
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, Constructor)]
#[tlv(22)]
pub struct SignatureInfo {
    signature_type: SignatureType,
    key_locator: Option<KeyLocator>,
    validity_period: Option<ValidityPeriod>,
}

impl SignatureInfo {
    pub fn signature_type(&self) -> VarNum {
        self.signature_type.signature_type
    }

    pub fn key_locator(&self) -> Option<&KeyLocatorData> {
        self.key_locator.as_ref().map(|x| &x.locator)
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
    fn signature_type(&self) -> u64;

    fn next_seq_num(&mut self) -> u64;

    fn certificate(&self) -> Option<Certificate>;

    fn sign(&self, data: &[u8]) -> Bytes;

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

pub trait SignMethodType {
    const SIGNATURE_TYPE: u64;
}

impl<T: SignMethod> SignMethod for &mut T {
    fn signature_type(&self) -> u64 {
        (**self).signature_type()
    }

    fn next_seq_num(&mut self) -> u64 {
        (**self).next_seq_num()
    }

    fn certificate(&self) -> Option<Certificate> {
        (**self).certificate()
    }

    fn sign(&self, data: &[u8]) -> Bytes {
        (**self).sign(data)
    }
}

impl<T: SignMethod + ?Sized> SignMethod for Box<T> {
    fn signature_type(&self) -> u64 {
        (**self).signature_type()
    }

    fn next_seq_num(&mut self) -> u64 {
        (**self).next_seq_num()
    }

    fn certificate(&self) -> Option<Certificate> {
        (**self).certificate()
    }

    fn sign(&self, data: &[u8]) -> Bytes {
        (**self).sign(data)
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct KnownSigners;

pub trait ToSigner {
    fn from_data(&self, data: Data<Bytes>) -> Option<Box<dyn SignMethod + Send + Sync>>;
}
impl ToSigner for KnownSigners {
    fn from_data(&self, data: Data<Bytes>) -> Option<Box<dyn SignMethod + Send + Sync>> {
        match get_signature_type(&data)? {
            signature_type::DIGEST_SHA256 => Some(Box::new(DigestSha256::from_data(data)?)),
            signature_type::SIGNATURE_SHA256_WITH_RSA => {
                Some(Box::new(SignatureSha256WithRsa::from_data(data)?))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct KnownVerifiers;

pub trait ToVerifier {
    fn from_data(&self, data: Data<Bytes>) -> Option<Box<dyn SignatureVerifier + Send + Sync>>;
}

impl ToVerifier for KnownVerifiers {
    fn from_data(&self, data: Data<Bytes>) -> Option<Box<dyn SignatureVerifier + Send + Sync>> {
        match get_signature_type(&data)? {
            signature_type::DIGEST_SHA256 => Some(Box::new(DigestSha256::from_data(data)?)),
            signature_type::SIGNATURE_SHA256_WITH_RSA => {
                Some(Box::new(SignatureSha256WithRsa::from_data(data)?))
            }
            _ => None,
        }
    }
}

pub trait SignatureVerifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool;

    fn certificate(&self) -> Option<Certificate>;

    fn from_data(data: Data<Bytes>) -> Option<Self>
    where
        Self: Sized;
}

impl<T> SignatureVerifier for &T
where
    T: SignatureVerifier,
{
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        (**self).verify(data, signature)
    }

    fn certificate(&self) -> Option<Certificate> {
        (**self).certificate()
    }

    fn from_data(_data: Data<Bytes>) -> Option<Self>
    where
        Self: Sized,
    {
        None
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DigestSha256 {
    seq_num: u64,
}

impl DigestSha256 {
    pub const fn new() -> Self {
        DigestSha256 { seq_num: 0 }
    }

    pub fn certificate() -> Certificate {
        let mut data = Data::new(Name::empty(), Bytes::new());
        data.set_meta_info(Some(MetaInfo {
            content_type: Some(ContentType {
                content_type: NonNegativeInteger::new(signature_type::DIGEST_SHA256 as u64),
            }),
            freshness_period: None,
            final_block_id: None,
        }));
        Certificate(data)
    }
}

impl SignMethodType for DigestSha256 {
    const SIGNATURE_TYPE: u64 = 0;
}

impl SignMethod for DigestSha256 {
    fn signature_type(&self) -> u64 {
        Self::SIGNATURE_TYPE
    }

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

    fn certificate(&self) -> Option<Certificate> {
        None
    }
}

impl SignatureVerifier for DigestSha256 {
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        let hashed = self.sign(data);
        hashed == signature
    }

    fn certificate(&self) -> Option<Certificate> {
        None
    }

    fn from_data(_data: Data<Bytes>) -> Option<Self>
    where
        Self: Sized,
    {
        Some(DigestSha256::new())
    }
}

#[derive(Clone, Debug)]
pub struct SignatureSha256WithRsaVerifier(pub RsaCertificate);

#[derive(Clone, Debug)]
pub struct SignatureSha256WithRsa {
    cert: RsaCertificate,
    seq_num: u64,
}

impl SignatureSha256WithRsa {
    pub fn new(cert: RsaCertificate) -> Self {
        Self { cert, seq_num: 0 }
    }
}

impl SignMethodType for SignatureSha256WithRsa {
    const SIGNATURE_TYPE: u64 = 1;
}

impl SignMethod for SignatureSha256WithRsa {
    fn signature_type(&self) -> u64 {
        Self::SIGNATURE_TYPE
    }

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

    fn certificate(&self) -> Option<Certificate> {
        Some(self.cert.to_certificate())
    }
}

impl SignatureVerifier for SignatureSha256WithRsa {
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        SignatureSha256WithRsaVerifier(self.cert.clone()).verify(data, signature)
    }

    fn certificate(&self) -> Option<Certificate> {
        Some(self.cert.to_certificate())
    }

    fn from_data(data: Data<Bytes>) -> Option<Self>
    where
        Self: Sized,
    {
        signature_type::ensure_signature_type(&data, signature_type::SIGNATURE_SHA256_WITH_RSA)?;
        Some(Self::new(RsaCertificate::new(Certificate(data))?))
    }
}

impl SignatureVerifier for SignatureSha256WithRsaVerifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        let mut hasher: Sha256 = Sha256::new();
        hasher.update(data);
        let hashed = hasher.finalize();

        self.0
            .public_key()
            .verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, &signature)
            .is_ok()
    }

    fn certificate(&self) -> Option<Certificate> {
        Some(self.0.to_certificate())
    }

    fn from_data(data: Data<Bytes>) -> Option<Self>
    where
        Self: Sized,
    {
        signature_type::ensure_signature_type(&data, signature_type::SIGNATURE_SHA256_WITH_RSA)?;
        Some(Self(RsaCertificate::new(Certificate(data))?))
    }
}
