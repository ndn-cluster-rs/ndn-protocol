//! Signing and verifying [`Interest`](crate::Interest)s and
//! [`Data`]s.
//!
//! Signing goes through the [`SignMethod`] trait and verifying through
//! [`SignatureVerifier`]; a type can implement either or both, and
//! [`DigestSha256`] and [`SignatureSha256WithRsa`] implement both, since
//! both take a certificate/key pair that's just as capable of checking a
//! signature as producing one. [`KnownSigners`]/[`KnownVerifiers`] can
//! build the right signer/verifier for a certificate purely from the
//! signature type it declares, for code that doesn't know in advance
//! which scheme it's dealing with.
//!
//! The rest of this module is the wire-format types that make up a
//! [`SignatureInfo`]/`InterestSignatureInfo` -- [`SignatureType`],
//! [`KeyLocator`], [`ValidityPeriod`], and so on. Most application code
//! only needs to read them back via [`SignatureInfo::key_locator`]/
//! `InterestSignatureInfo::key_locator` after verifying.

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

/// The signature type numbers used in a [`SignatureType`], identifying
/// which signing scheme was used.
pub mod signature_type {
    use ndn_tlv::TlvEncode;

    use crate::Data;

    /// A plain SHA-256 digest, with no key involved (see [`DigestSha256`](crate::DigestSha256)).
    pub const DIGEST_SHA256: usize = 0;
    /// An RSA signature over a SHA-256 digest (see [`SignatureSha256WithRsa`](crate::SignatureSha256WithRsa)).
    pub const SIGNATURE_SHA256_WITH_RSA: usize = 1;
    /// An ECDSA signature over a SHA-256 digest. Not implemented by this crate.
    pub const SIGNATURE_SHA256_WITH_ECDSA: usize = 3;
    /// A HMAC over a SHA-256 digest. Not implemented by this crate.
    pub const SIGNATRUE_HMAC_WITH_SHA256: usize = 4;
    /// An Ed25519 signature. Not implemented by this crate.
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

/// Which signing scheme a signature was produced with -- see the
/// [`signature_type`] module for the well-known values.
#[derive(
    Debug, Tlv, PartialEq, Eq, Clone, Hash, From, Into, AsRef, AsMut, Display, Constructor,
)]
#[tlv(27)]
pub struct SignatureType {
    signature_type: VarNum,
}

/// A digest identifying a public key, used as a compact alternative to a
/// full [`Name`] in a [`KeyLocator`].
#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, From, Into, AsRef, AsMut, Constructor)]
#[tlv(29)]
pub struct KeyDigest {
    data: Bytes,
}

/// What a [`KeyLocator`] points at: either the signing certificate's
/// [`Name`] (the `Name` variant), or a [`KeyDigest`] of its key (the
/// `KeyDigest` variant).
#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash)]
pub enum KeyLocatorData {
    /// The signing certificate's name.
    Name(Name),
    /// A digest of the signing key.
    KeyDigest(KeyDigest),
}

impl KeyLocatorData {
    /// The name, if this locator points at one.
    pub fn as_name(&self) -> Option<&Name> {
        if let Self::Name(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// The key digest, if this locator points at one.
    pub fn as_key_digest(&self) -> Option<&KeyDigest> {
        if let Self::KeyDigest(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

/// Identifies the key used to produce a signature, so a verifier knows
/// which certificate to check it against.
#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, AsRef, AsMut, Constructor, From, Into)]
#[tlv(28)]
pub struct KeyLocator {
    locator: KeyLocatorData,
}

impl KeyLocator {
    /// What the locator points at.
    pub fn locator(&self) -> &KeyLocatorData {
        &self.locator
    }
}

/// A point in time in the `YYYYMMDDTHHMMSS` format NDN certificate
/// validity periods use, e.g. `20240301T200915`.
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

/// The start of a [`ValidityPeriod`].
#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, Constructor)]
#[tlv(254)]
pub struct NotBefore {
    /// The earliest time the signature is considered valid.
    pub not_before: Timestamp,
}

/// The end of a [`ValidityPeriod`].
#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, Constructor)]
#[tlv(255)]
pub struct NotAfter {
    /// The latest time the signature is considered valid.
    pub not_after: Timestamp,
}

/// The time range a certificate's signature is valid within -- see [`Data::sign_cert`](crate::Data::sign_cert).
#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, Constructor)]
#[tlv(253)]
pub struct ValidityPeriod {
    /// The start of the validity period.
    pub not_before: NotBefore,
    /// The end of the validity period.
    pub not_after: NotAfter,
}

/// Metadata attached to a signed [`Data`] packet describing how it was
/// signed: the [`SignatureType`], the [`KeyLocator`] identifying the
/// signing key, and, for certificates, a [`ValidityPeriod`].
#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, Constructor)]
#[tlv(22)]
pub struct SignatureInfo {
    signature_type: SignatureType,
    key_locator: Option<KeyLocator>,
    validity_period: Option<ValidityPeriod>,
}

impl SignatureInfo {
    /// The signature type number.
    pub fn signature_type(&self) -> VarNum {
        self.signature_type.signature_type
    }

    /// What the key locator points at, if set.
    pub fn key_locator(&self) -> Option<&KeyLocatorData> {
        self.key_locator.as_ref().map(|x| &x.locator)
    }
}

/// The raw signature bytes produced by signing a [`Data`] packet.
#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, AsRef, AsMut, Constructor, From, Into)]
#[tlv(23)]
pub struct SignatureValue {
    data: Bytes,
}

/// A random value included in an `InterestSignatureInfo` to make each
/// signed Interest unique, guarding against replay.
#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, AsRef, AsMut, Constructor, From, Into)]
#[tlv(38)]
pub struct SignatureNonce {
    data: Bytes,
}

/// A signing timestamp (Unix time in milliseconds) included in an
/// `InterestSignatureInfo`, guarding against replay of old signed Interests.
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

/// A signing sequence number included in an `InterestSignatureInfo`,
/// guarding against replay: a verifier can reject a signature whose
/// sequence number isn't greater than the last one seen from that signer.
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

/// Metadata attached to a signed [`Interest`](crate::Interest) describing
/// how it was signed. Mirrors [`SignatureInfo`], but with the extra
/// replay-protection fields ([`SignatureNonce`], [`SignatureTime`],
/// [`SignatureSeqNum`]) signed Interests carry instead of a validity period.
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
    /// The signature type number.
    pub fn signature_type(&self) -> VarNum {
        self.signature_type.signature_type
    }

    /// What the key locator points at, if set.
    pub fn key_locator(&self) -> Option<&KeyLocatorData> {
        self.key_locator.as_ref().map(|x| &x.locator)
    }

    /// The signing nonce, if included.
    pub fn nonce(&self) -> Option<&Bytes> {
        self.nonce.as_ref().map(|x| &x.data)
    }

    /// The signing timestamp (Unix time in milliseconds), if included.
    pub fn time(&self) -> Option<NonNegativeInteger> {
        self.time.as_ref().map(|x| x.data)
    }

    /// The signing sequence number, if included.
    pub fn seq_num(&self) -> Option<NonNegativeInteger> {
        self.seq_num.as_ref().map(|x| x.data)
    }
}

/// The raw signature bytes produced by signing an
/// [`Interest`](crate::Interest).
#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, From, Into, AsRef, AsMut, Constructor)]
#[tlv(46)]
pub struct InterestSignatureValue {
    data: Bytes,
}

/// Something that can sign [`Interest`](crate::Interest)s and
/// [`Data`] -- see [`DigestSha256`] and
/// [`SignatureSha256WithRsa`] for the implementations this crate provides.
pub trait SignMethod {
    /// The signature type number this method produces (see [`signature_type`]).
    fn signature_type(&self) -> u64;

    /// Returns the next signing sequence number, advancing internal state
    /// so each call returns a new value.
    fn next_seq_num(&mut self) -> u64;

    /// The certificate this method signs with, if any (e.g. `None` for
    /// [`DigestSha256`], which signs without a key).
    fn certificate(&self) -> Option<Certificate>;

    /// Signs `data`, returning the raw signature bytes.
    fn sign(&self, data: &[u8]) -> Bytes;

    /// The current time, used as the default signing timestamp. Provided
    /// so it doesn't need to be implemented by every `SignMethod`.
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

/// Associates a [`SignMethod`] implementation with its fixed signature
/// type number, so it can be checked against a certificate's declared type
/// without needing an instance (see [`SignatureSha256WithRsaVerifier::from_data`]
/// and similar).
pub trait SignMethodType {
    /// This signing scheme's signature type number (see [`signature_type`]).
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

/// Builds a [`SignMethod`] for any signature type this crate implements,
/// purely from a certificate's declared signature type -- see [`ToSigner`].
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct KnownSigners;

/// Implemented by types that can produce a [`SignMethod`] for a
/// certificate, without the caller needing to know its signature type in
/// advance.
pub trait ToSigner {
    /// Builds a signer for `data`'s declared signature type, or `None` if
    /// it's not one this implementation recognizes.
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

/// Builds a [`SignatureVerifier`] for any signature type this crate
/// implements, purely from a certificate's declared signature type -- see
/// [`ToVerifier`].
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct KnownVerifiers;

/// Implemented by types that can produce a [`SignatureVerifier`] for a
/// certificate, without the caller needing to know its signature type in
/// advance. Mirrors [`ToSigner`] for the verifying side.
pub trait ToVerifier {
    /// Builds a verifier for `data`'s declared signature type, or `None`
    /// if it's not one this implementation recognizes.
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

/// Something that can verify signatures produced by a [`SignMethod`] -- see
/// [`DigestSha256`] and [`SignatureSha256WithRsa`] for the implementations
/// this crate provides.
pub trait SignatureVerifier {
    /// Returns whether `signature` is a valid signature of `data`.
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool;

    /// The certificate this verifier checks against, if any (e.g. `None`
    /// for [`DigestSha256`], which verifies without a key).
    fn certificate(&self) -> Option<Certificate>;

    /// Builds a verifier from a certificate [`Data`] packet, or `None` if
    /// its signature type doesn't match this implementation.
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

/// Signs and verifies with a plain SHA-256 digest -- no key involved, so it
/// only proves data wasn't corrupted in transit, not who sent it. See
/// [`SignatureSha256WithRsa`] for a scheme that actually authenticates.
#[derive(Clone, Copy, Debug)]
pub struct DigestSha256 {
    seq_num: u64,
}

impl DigestSha256 {
    /// Creates a new `DigestSha256` with its sequence number reset to `0`.
    pub const fn new() -> Self {
        DigestSha256 { seq_num: 0 }
    }

    /// A placeholder certificate declaring the digest signature type, for
    /// code paths that need a [`Certificate`] but `DigestSha256` doesn't
    /// actually have a key to certify.
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

/// Verifies `SignatureSha256WithRsa` signatures against an
/// [`RsaCertificate`]'s public key, without needing its private key.
#[derive(Clone, Debug)]
pub struct SignatureSha256WithRsaVerifier(pub RsaCertificate);

/// Signs with RSA over a SHA-256 digest, and verifies the same way.
#[derive(Clone, Debug)]
pub struct SignatureSha256WithRsa {
    cert: RsaCertificate,
    seq_num: u64,
}

impl SignatureSha256WithRsa {
    /// Creates a new `SignatureSha256WithRsa` signing/verifying with
    /// `cert`, with its sequence number reset to `0`.
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
