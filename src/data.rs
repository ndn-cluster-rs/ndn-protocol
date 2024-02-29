use bytes::Bytes;
use derive_more::{AsMut, AsRef, Display, From, Into};
use ndn_tlv::{NonNegativeInteger, Tlv, TlvDecode, TlvEncode, VarNum};

use crate::{
    signature::SignMethod, Certificate, Name, NameComponent, SignatureInfo, SignatureType,
    SignatureValue,
};

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, Display, Default, From, Into, AsRef, AsMut)]
#[tlv(24)]
#[display(fmt = "{}", content_type)]
pub struct ContentType {
    pub content_type: NonNegativeInteger,
}

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
    pub freshness_period: NonNegativeInteger,
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, From, Into, AsRef, AsMut)]
#[tlv(26)]
pub struct FinalBlockId {
    pub final_block_id: NameComponent,
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, Default, From, AsRef, AsMut)]
#[tlv(21)]
pub struct Content<T> {
    pub data: T,
}

#[derive(Debug, Tlv, PartialEq, Eq, Default, Clone, Hash)]
#[tlv(20)]
pub struct MetaInfo {
    pub content_type: Option<ContentType>,
    pub freshness_period: Option<FreshnessPeriod>,
    pub final_block_id: Option<FinalBlockId>,
}

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
    pub const BLOB: Self = Self::new(0);
    pub const LINK: Self = Self::new(1);
    pub const KEY: Self = Self::new(2);
    pub const NACK: Self = Self::new(3);

    pub const fn new(typ: u64) -> Self {
        Self {
            content_type: NonNegativeInteger::new(typ),
        }
    }
}

impl FreshnessPeriod {
    pub fn new(period: u64) -> Self {
        Self {
            freshness_period: NonNegativeInteger::new(period),
        }
    }
}

impl Data<Bytes> {
    pub fn content_decode<U>(self) -> Data<U>
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
    T: Clone,
    T: TlvEncode,
{
    pub fn new(name: Name, content: T) -> Self {
        Data {
            name,
            meta_info: Some(MetaInfo {
                content_type: Some(ContentType {
                    content_type: 0u8.into(),
                }),
                freshness_period: None,
                final_block_id: None,
            }),
            content: Some(Content { data: content }),
            signature_info: None,
            signature_value: None,
        }
    }

    pub fn name(&self) -> &Name {
        &self.name
    }

    pub fn set_name(&mut self, name: Name) -> &mut Self {
        self.name = name;
        self
    }

    pub fn meta_info(&self) -> &Option<MetaInfo> {
        &self.meta_info
    }

    pub fn set_meta_info(&mut self, meta_info: Option<MetaInfo>) -> &mut Self {
        self.meta_info = meta_info;
        self
    }

    pub fn content(&self) -> Option<T> {
        self.content.as_ref().map(|x| x.data.clone())
    }

    pub fn set_content(&mut self, content: Option<T>) -> &mut Self {
        self.content = content.map(|data| Content { data });
        self
    }

    pub fn sign<S>(&mut self, sign_method: &mut S)
    where
        S: SignMethod,
    {
        self.signature_info = Some(SignatureInfo::new(
            SignatureType::new(VarNum::from(S::SIGNATURE_TYPE)),
            sign_method.certificate().locator(),
        ));

        let mut signed_portion = self.encode();

        // Skip TLV-Type and TLV-Length
        let _ = VarNum::decode(&mut signed_portion);
        let _ = VarNum::decode(&mut signed_portion);

        let signature = sign_method.sign(&signed_portion);
        self.signature_value = Some(SignatureValue::new(signature));
    }

    pub fn signature_info(&self) -> Option<&SignatureInfo> {
        self.signature_info.as_ref()
    }

    pub fn is_signed(&self) -> bool {
        self.signature_info.is_some()
    }
}
