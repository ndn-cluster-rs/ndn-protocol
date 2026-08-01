//! [`Data`], the packet returned in response to an [`Interest`].
//!
//! Like [`Interest`], `Data` is generic over its content
//! type, so a payload can be carried either as raw [`Bytes`] or as a
//! concrete type that implements
//! [`ndn_tlv::TlvEncode`]/[`ndn_tlv::TlvDecode`].

use bytes::{Buf, Bytes};
use derive_more::{AsMut, AsRef, Display, From, Into};
use ndn_tlv::{find_tlv, NonNegativeInteger, Tlv, TlvDecode, TlvEncode, VarNum};
use sha2::{Digest, Sha256};

use crate::{
    error::VerifyError,
    signature::{SignMethod, SignatureVerifier, ValidityPeriod},
    Interest, Name, NameComponent, SignatureInfo, SignatureType, SignatureValue,
};

/// What kind of content a [`Data`] packet carries -- see the associated
/// constants ([`ContentType::BLOB`], [`ContentType::LINK`], etc.) for the
/// well-known values.
#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, Display, Default, From, Into, AsRef, AsMut)]
#[tlv(24)]
#[display(fmt = "{}", content_type)]
pub struct ContentType {
    /// The raw content type number.
    pub content_type: NonNegativeInteger,
}

/// How long, in milliseconds, this Data should be considered fresh for
/// after being received. A consumer requiring fresh Data (see
/// [`MustBeFresh`](crate::MustBeFresh)) won't accept it once this expires.
#[derive(
    Debug,
    Tlv,
    PartialEq,
    Eq,
    Clone,
    Hash,
    PartialOrd,
    Ord,
    Display,
    Default,
    From,
    Into,
    AsRef,
    AsMut,
)]
#[tlv(25)]
#[display(fmt = "{}", freshness_period)]
pub struct FreshnessPeriod {
    /// The freshness period in milliseconds.
    pub freshness_period: NonNegativeInteger,
}

/// The name component of the final (last) piece of a segmented object,
/// letting a consumer detect when it has fetched every segment.
#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, From, Into, AsRef, AsMut)]
#[tlv(26)]
pub struct FinalBlockId {
    /// The final segment's name component.
    pub final_block_id: NameComponent,
}

/// The Data packet's payload.
#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, Default, From, AsRef, AsMut)]
#[tlv(21)]
pub struct Content<T> {
    /// The payload itself.
    pub data: T,
}

/// Metadata describing a [`Data`] packet's content: its [`ContentType`],
/// [`FreshnessPeriod`], and [`FinalBlockId`], all optional.
#[derive(Debug, Tlv, PartialEq, Eq, Default, Clone, Hash)]
#[tlv(20)]
pub struct MetaInfo {
    /// What kind of content this is.
    pub content_type: Option<ContentType>,
    /// How long the content stays fresh for.
    pub freshness_period: Option<FreshnessPeriod>,
    /// The final segment's name component, for segmented content.
    pub final_block_id: Option<FinalBlockId>,
}

/// The packet returned in response to a matching [`Interest`].
///
/// `T` is the type the content decodes/encodes as; use [`Bytes`] to work
/// with the raw payload, or a type implementing
/// [`ndn_tlv::TlvEncode`]/[`ndn_tlv::TlvDecode`] to work with it directly.
#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash)]
#[tlv(6)]
pub struct Data<T> {
    name: Name,
    meta_info: Option<MetaInfo>,
    content: Option<Content<T>>,
    signature_info: Option<SignatureInfo>,
    signature_value: Option<SignatureValue>,
}

impl ContentType {
    /// Regular, opaque application data.
    pub const BLOB: Self = Self::new(0);
    /// A link to other Data.
    pub const LINK: Self = Self::new(1);
    /// A public key.
    pub const KEY: Self = Self::new(2);
    /// A negative acknowledgement, indicating an Interest could not be satisfied.
    pub const NACK: Self = Self::new(3);

    /// Creates a `ContentType` from a raw type number.
    pub const fn new(typ: u64) -> Self {
        Self {
            content_type: NonNegativeInteger::new(typ),
        }
    }
}

impl FreshnessPeriod {
    /// Creates a `FreshnessPeriod` of `period` milliseconds.
    pub fn new(period: u64) -> Self {
        Self {
            freshness_period: NonNegativeInteger::new(period),
        }
    }
}

impl Data<Bytes> {
    /// Decodes the raw content into a concrete type `U`, converting a `Data<Bytes>` into the
    /// corresponding `Data<U>`.
    ///
    /// If decoding fails, or there was no content to begin with, the
    /// returned Data simply has none.
    pub fn decode_content<U>(self) -> Data<U>
    where
        U: TlvDecode,
    {
        Data {
            content: self
                .content
                .and_then(|mut x| U::decode(&mut x.data).ok())
                .map(|data| Content { data }),
            name: self.name,
            meta_info: self.meta_info,
            signature_info: self.signature_info,
            signature_value: self.signature_value,
        }
    }
}

impl<T> Data<T>
where
    T: TlvEncode,
{
    /// Creates a new, unsigned Data packet for `name` carrying `content`,
    /// with its content type defaulted to [`ContentType::BLOB`].
    pub const fn new(name: Name, content: T) -> Self {
        Data {
            name,
            meta_info: Some(MetaInfo {
                content_type: Some(ContentType {
                    content_type: NonNegativeInteger::U8(0),
                }),
                freshness_period: None,
                final_block_id: None,
            }),
            content: Some(Content { data: content }),
            signature_info: None,
            signature_value: None,
        }
    }

    /// The Data packet's name.
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Sets the Data packet's name.
    pub fn set_name(&mut self, name: Name) -> &mut Self {
        self.name = name;
        self
    }

    /// The Data packet's [`MetaInfo`], if set.
    pub fn meta_info(&self) -> &Option<MetaInfo> {
        &self.meta_info
    }

    /// Sets the Data packet's [`MetaInfo`], or clears it if `None`.
    pub fn set_meta_info(&mut self, meta_info: Option<MetaInfo>) -> &mut Self {
        self.meta_info = meta_info;
        self
    }

    /// The Data packet's content, if set.
    pub fn content(&self) -> Option<&T> {
        self.content.as_ref().map(|x| &x.data)
    }

    /// Sets the Data packet's content, or clears it if `None`.
    pub fn set_content(&mut self, content: Option<T>) -> &mut Self {
        self.content = content.map(|data| Content { data });
        self
    }

    /// Encodes the content to its raw TLV bytes, the inverse of
    /// [`Data::decode_content`].
    pub fn encode_content(self) -> Data<Bytes> {
        Data {
            name: self.name,
            meta_info: self.meta_info,
            content: self.content.map(|x| Content {
                data: x.data.encode(),
            }),
            signature_info: self.signature_info,
            signature_value: self.signature_value,
        }
    }

    fn signable_portion(&self) -> Bytes {
        let mut data = self.encode();
        let _ = VarNum::decode(&mut data);
        let _ = VarNum::decode(&mut data);

        let mut end = data.clone();
        let _ = find_tlv::<SignatureValue>(&mut end, false);

        data.truncate(data.len() - end.remaining());
        data
    }

    fn sign_internal<S>(&mut self, sign_method: &S, signature_info: SignatureInfo)
    where
        S: SignMethod,
    {
        self.signature_info = Some(signature_info);

        let mut signed_portion = self.encode();

        // Skip TLV-Type and TLV-Length
        let _ = VarNum::decode(&mut signed_portion);
        let _ = VarNum::decode(&mut signed_portion);

        let signature = sign_method.sign(&signed_portion);
        self.signature_value = Some(SignatureValue::new(signature));
    }

    /// Signs the Data packet with `sign_method`.
    pub fn sign<S>(&mut self, sign_method: &mut S)
    where
        S: SignMethod,
    {
        self.sign_internal(
            sign_method,
            SignatureInfo::new(
                SignatureType::new(VarNum::from(sign_method.signature_type())),
                sign_method.certificate().map(|x| x.name_locator()),
                None,
            ),
        )
    }

    /// Signs the Data packet with `sign_method`, additionally recording a
    /// [`ValidityPeriod`] the signature is only considered valid within.
    /// Used to sign certificates, which need an expiry.
    pub fn sign_cert<S>(&mut self, sign_method: &S, validity_period: ValidityPeriod)
    where
        S: SignMethod,
    {
        self.sign_internal(
            sign_method,
            SignatureInfo::new(
                SignatureType::new(VarNum::from(sign_method.signature_type())),
                sign_method.certificate().map(|x| x.name_locator()),
                Some(validity_period),
            ),
        )
    }

    /// The signature info added by [`Data::sign`]/[`Data::sign_cert`], if the Data is signed.
    pub fn signature_info(&self) -> Option<&SignatureInfo> {
        self.signature_info.as_ref()
    }

    /// Whether the Data packet carries a signature.
    pub fn is_signed(&self) -> bool {
        self.signature_info.is_some()
    }

    /// Returns whether this Data satisfies `interest` by name, respecting
    /// [`CanBePrefix`](crate::CanBePrefix) and an implicit digest
    /// component, if present.
    ///
    /// This only checks the name; it doesn't check
    /// [`MustBeFresh`](crate::MustBeFresh), since freshness depends on
    /// when the Data was received, which this packet doesn't know.
    pub fn matches_interest<D>(&self, interest: &Interest<D>) -> bool
    where
        D: TlvEncode + TlvDecode,
    {
        // If `name` contains an ImplicitSha256DigestComponent, check that it's correct
        if let Some(NameComponent::ImplicitSha256DigestComponent(component)) =
            interest.name().components.last()
        {
            let mut hasher = Sha256::new();
            hasher.update(self.encode());
            let hash = hasher.finalize();
            let hash: &[u8] = &hash;
            if &component.name != hash {
                return false;
            }
        }

        // If CanBePrefix is set, just check if name is a prefix
        if interest.can_be_prefix() {
            self.name.has_prefix(interest.name())
        } else {
            for (c1, c2) in self.name().iter().zip(interest.name().iter()) {
                if matches!(c2, NameComponent::ImplicitSha256DigestComponent(_)) {
                    continue;
                }
                if c1 != c2 {
                    return false;
                }
            }
            true
        }
    }

    /// Verify the signature of this Data packet with the given SignMethod
    pub fn verify<S>(&self, sign_method: &S) -> Result<(), VerifyError>
    where
        S: SignatureVerifier,
        S: ?Sized,
    {
        let Some(ref signature_value) = self.signature_value else {
            return Err(VerifyError::MissingSignatureInfo);
        };

        let signable_portion = self.signable_portion();

        let success = sign_method.verify(&signable_portion, signature_value.as_ref());

        success.then_some(()).ok_or(VerifyError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use bytes::Bytes;
    use ndn_tlv::TlvDecode;

    use crate::{Content, Data, Name, RsaCertificate, SafeBag, SignatureSha256WithRsa};

    #[test]
    fn rsa_signature() {
        const SAFEBAG: &[u8] = b"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\
g==";

        let safebag_data = base64::engine::general_purpose::STANDARD
            .decode(SAFEBAG)
            .unwrap();
        let safebag = SafeBag::decode(&mut Bytes::from(safebag_data)).unwrap();

        let cert = RsaCertificate::from_safebag(safebag, "test").unwrap();

        let mut data = Data {
            name: Name::from_str("ndn:/test/test/asd").unwrap(),
            meta_info: None,
            content: Some(Content { data: () }),
            signature_info: None,
            signature_value: None,
        };

        let mut signer = SignatureSha256WithRsa::new(cert.clone());
        data.sign(&mut signer);

        assert!(data.verify(&signer).is_ok());
    }
}
