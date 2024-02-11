use bytes::{BufMut, Bytes, BytesMut};
use ndn_tlv::{Tlv, TlvDecode, TlvEncode, VarNum};

use crate::{
    signature::{InterestSignatureInfo, InterestSignatureValue, SignMethod, SignatureSeqNum},
    Name, NameComponent, SignatureInfo, SignatureType,
};

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(33)]
pub struct CanBePrefix;

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(18)]
pub struct MustBeFresh;

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(30)]
pub struct ForwardingHint {
    name: Name,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(10)]
pub struct Nonce {
    nonce: [u8; 4],
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(12)]
pub struct InterestLifetime {
    lifetime: VarNum,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(34)]
pub struct HopLimit {
    limit: u8,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(36)]
pub struct ApplicationParameters {
    data: Bytes,
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(5)]
pub struct Interest {
    name: Name,
    can_be_prefix: Option<CanBePrefix>,
    must_be_fresh: Option<MustBeFresh>,
    forwarding_hint: Option<ForwardingHint>,
    nonce: Option<Nonce>,
    interest_lifetime: Option<InterestLifetime>,
    hop_limit: Option<HopLimit>,
    application_parameters: Option<ApplicationParameters>,
    signature_info: Option<InterestSignatureInfo>,
}

pub struct SignedInterest {
    interest: Interest,
    signature_value: InterestSignatureValue,
}

impl Tlv for SignedInterest {
    const TYP: usize = 5;

    fn inner_size(&self) -> usize {
        self.interest.inner_size() + self.signature_value.size()
    }
}

impl TlvEncode for SignedInterest {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.size());

        let mut interest = self.interest.encode();
        let _ = VarNum::decode(&mut interest);
        let _ = VarNum::decode(&mut interest);

        bytes.put(VarNum::from(Self::TYP).encode());
        bytes.put(VarNum::from(self.size()).encode());
        bytes.put(interest);
        bytes.put(self.signature_value.encode());
        bytes.freeze()
    }

    fn size(&self) -> usize {
        let inner_size = self.inner_size();
        VarNum::from(Self::TYP).size() + VarNum::from(inner_size).size() + inner_size
    }
}

impl Interest {
    pub fn new(name: Name) -> Self {
        Self {
            name,
            can_be_prefix: None,
            must_be_fresh: None,
            forwarding_hint: None,
            nonce: None,
            interest_lifetime: None,
            hop_limit: None,
            application_parameters: None,
            signature_info: None,
        }
    }

    pub fn set_name(&mut self, name: Name) -> &mut Self {
        self.name = name;
        self
    }

    pub fn name(&self) -> &Name {
        &self.name
    }

    pub fn set_can_be_prefix(&mut self, can_be_prefix: bool) -> &mut Self {
        self.can_be_prefix = can_be_prefix.then_some(CanBePrefix);
        self
    }

    pub fn can_be_prefix(&self) -> bool {
        self.can_be_prefix.is_some()
    }

    pub fn set_must_be_fresh(&mut self, must_be_fresh: bool) -> &mut Self {
        self.must_be_fresh = must_be_fresh.then_some(MustBeFresh);
        self
    }

    pub fn must_be_fresh(&self) -> bool {
        self.must_be_fresh.is_some()
    }

    pub fn set_forwarding_hint(&mut self, forwarding_hint: Option<Name>) -> &mut Self {
        self.forwarding_hint = forwarding_hint.map(|name| ForwardingHint { name });
        self
    }

    pub fn forwarding_hint(&self) -> Option<&Name> {
        self.forwarding_hint.as_ref().map(|x| &x.name)
    }

    pub fn set_nonce(&mut self, nonce: Option<[u8; 4]>) -> &mut Self {
        self.nonce = nonce.map(|nonce| Nonce { nonce });
        self
    }

    pub fn nonce(&self) -> Option<&[u8; 4]> {
        self.nonce.as_ref().map(|x| &x.nonce)
    }

    pub fn set_interest_lifetime(&mut self, interest_lifetime: Option<u64>) -> &mut Self {
        self.interest_lifetime = interest_lifetime.map(|lifetime| InterestLifetime {
            lifetime: lifetime.into(),
        });
        self
    }

    pub fn interest_lifetime(&self) -> Option<u64> {
        self.interest_lifetime.as_ref().map(|x| x.lifetime.into())
    }

    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) -> &mut Self {
        self.hop_limit = hop_limit.map(|limit| HopLimit { limit });
        self
    }

    pub fn hop_limit(&self) -> Option<u8> {
        self.hop_limit.as_ref().map(|x| x.limit)
    }

    pub fn sign<T: SignMethod>(mut self, sign_method: &mut T) -> SignedInterest {
        self.name
            .components
            .retain(|x| !matches!(x, NameComponent::ParametersSha256DigestComponent(_)));
        if self.application_parameters.is_none() {
            self.application_parameters = Some(ApplicationParameters { data: Bytes::new() });
        }

        let seq_num = sign_method.next_seq_num();
        self.signature_info = Some(InterestSignatureInfo {
            signature_type: SignatureType {
                signature_type: T::SIGNATURE_TYPE.into(),
            },
            key_locator: sign_method.locator(),
            nonce: None,
            time: None, // Some(sign_method.time()),
            seq_num: Some(SignatureSeqNum {
                data: seq_num.into(),
            }),
        });

        let mut bytes = self.encode();
        let _ = VarNum::decode(&mut bytes);
        let _ = VarNum::decode(&mut bytes);

        let signature = sign_method.sign(bytes);

        SignedInterest {
            interest: self,
            signature_value: InterestSignatureValue { data: signature },
        }
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use crate::signature::DigestSha256;

    use super::*;

    #[test]
    fn simple_usage() {
        let mut interest = Interest::new(Name::from_str("ndn:/hello/world").unwrap());
        interest
            .set_can_be_prefix(true)
            .set_hop_limit(Some(20))
            .set_interest_lifetime(Some(10_000));

        assert_eq!(
            interest,
            Interest {
                name: Name::from_str("ndn:/hello/world").unwrap(),
                can_be_prefix: Some(CanBePrefix),
                must_be_fresh: None,
                forwarding_hint: None,
                nonce: None,
                interest_lifetime: Some(InterestLifetime {
                    lifetime: 10000.into()
                }),
                hop_limit: Some(HopLimit { limit: 20 }),
                application_parameters: None,
                signature_info: None,
            }
        );
    }

    #[test]
    fn sha256_interest() {
        let interest = Interest::new(Name::from_str("ndn:/hello/world").unwrap());
        let mut signer = DigestSha256::new();
        let signed_interest = interest.sign(&mut signer);

        let signable = [
            7, 14, // Name
            8, 5, b'h', b'e', b'l', b'l', b'o', 8, 5, b'w', b'o', b'r', b'l', b'd', //
            36, 0, // ApplicationParameters
            44, 6, // SignatureInfo
            27, 1, // Signature Type
            0, //
            42, 1, 0, // seq num
        ];

        let mut hasher = Sha256::new();
        hasher.update(signable);

        let mut full_record = Vec::new();
        full_record.extend([5, 62]);
        full_record.extend(signable);
        full_record.extend([46, 32]);
        full_record.extend(hasher.finalize());

        assert_eq!(<Vec<u8>>::from(signed_interest.encode()), full_record);
    }
}