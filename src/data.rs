use ndn_tlv::{NonNegativeInteger, Tlv, TlvDecode, TlvEncode, VarNum};

use crate::{
    signature::SignMethod, Name, NameComponent, SignatureInfo, SignatureType, SignatureValue,
};

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(24)]
pub struct ContentType {
    pub content_type: NonNegativeInteger,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(25)]
pub struct FreshnessPeriod {
    pub freshness_period: NonNegativeInteger,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(26)]
pub struct FinalBlockId {
    pub final_block_id: NameComponent,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(21)]
pub struct Content<T> {
    pub data: T,
}

#[derive(Debug, Tlv, PartialEq, Eq, Default)]
#[tlv(20)]
pub struct MetaInfo {
    pub content_type: Option<ContentType>,
    pub freshness_period: Option<FreshnessPeriod>,
    pub final_block_id: Option<FinalBlockId>,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(6)]
pub struct Data<T> {
    name: Name,
    meta_info: Option<MetaInfo>,
    content: Option<Content<T>>,
    signature_info: Option<SignatureInfo>,
    signature_value: Option<SignatureValue>,
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
        self.signature_info = Some(SignatureInfo {
            signature_type: SignatureType {
                signature_type: VarNum::from(S::SIGNATURE_TYPE),
            },
            key_locator: sign_method.locator(),
        });

        let mut signed_portion = self.encode();

        // Skip TLV-Type and TLV-Length
        let _ = VarNum::decode(&mut signed_portion);
        let _ = VarNum::decode(&mut signed_portion);

        println!("signed portion: {:?}", &signed_portion);

        let signature = sign_method.sign(signed_portion);
        self.signature_value = Some(SignatureValue { data: signature });
    }
}
