use bytes::{Buf, BufMut, Bytes, BytesMut};
use ndn_tlv::{find_tlv, NonNegativeInteger, Tlv, TlvDecode, TlvEncode, VarNum};
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};

use crate::{
    name::ParametersSha256DigestComponent,
    signature::{
        InterestSignatureInfo, InterestSignatureValue, SignMethod, SignatureNonce, SignatureSeqNum,
    },
    Name, NameComponent, SignatureType,
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
    lifetime: NonNegativeInteger,
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

#[derive(Debug, PartialEq, Eq)]
pub struct SignSettings {
    pub include_time: bool,
    pub include_seq_num: bool,
    pub nonce_length: usize,
}

impl Default for SignSettings {
    fn default() -> Self {
        Self {
            include_time: true,
            include_seq_num: true,
            nonce_length: 8,
        }
    }
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
        bytes.put(VarNum::from(self.inner_size()).encode());
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

    /// Creates the `ParametersSha256DigestComponent` part of the name.
    ///
    /// The component will be automatically added to the name when signing the interest, so this is
    /// only useful for unsigned interests.
    pub fn make_parameters_digest(data: Bytes) -> ParametersSha256DigestComponent {
        let mut hasher = Sha256::new();
        hasher.update(VarNum::from(ApplicationParameters::TYP).encode());
        hasher.update(VarNum::from(data.len()).encode());
        hasher.update(&data);
        ParametersSha256DigestComponent {
            name: hasher.finalize().into(),
        }
    }

    /// Adds a `ParametersSha256DigestComponent` to the end of the name
    ///
    /// The component will be automatically added to the name when signing the interest, so this is
    /// only useful for unsigned interests.
    ///
    /// Empty application parameters will be set if none are set currently.
    /// Any existing `ParametersSha256DigestComponent` will be removed.
    pub fn add_parameters_digest(&mut self) -> &mut Self {
        self.name
            .components
            .retain(|x| !matches!(x, NameComponent::ParametersSha256DigestComponent(_)));

        if self.application_parameters.is_none() {
            self.application_parameters = Some(ApplicationParameters { data: Bytes::new() });
        }

        self.name
            .components
            .push(NameComponent::ParametersSha256DigestComponent(
                Self::make_parameters_digest(
                    self.application_parameters.as_ref().unwrap().data.clone(),
                ),
            ));
        self
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

    pub fn set_interest_lifetime(
        &mut self,
        interest_lifetime: Option<NonNegativeInteger>,
    ) -> &mut Self {
        self.interest_lifetime = interest_lifetime.map(|lifetime| InterestLifetime { lifetime });
        self
    }

    pub fn interest_lifetime(&self) -> Option<NonNegativeInteger> {
        self.interest_lifetime.as_ref().map(|x| x.lifetime)
    }

    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) -> &mut Self {
        self.hop_limit = hop_limit.map(|limit| HopLimit { limit });
        self
    }

    pub fn hop_limit(&self) -> Option<u8> {
        self.hop_limit.as_ref().map(|x| x.limit)
    }

    pub fn set_application_parameters(&mut self, params: Option<Bytes>) -> &mut Self {
        self.application_parameters = params.map(|data| ApplicationParameters { data });
        self
    }

    pub fn application_parameters(&self) -> Option<&Bytes> {
        self.application_parameters.as_ref().map(|x| &x.data)
    }

    pub fn sign<T: SignMethod>(
        mut self,
        sign_method: &mut T,
        settings: SignSettings,
    ) -> SignedInterest {
        self.name
            .components
            .retain(|x| !matches!(x, NameComponent::ParametersSha256DigestComponent(_)));
        if self.application_parameters.is_none() {
            self.application_parameters = Some(ApplicationParameters { data: Bytes::new() });
        }

        let nonce = if settings.nonce_length > 0 {
            let mut rng = rand::rngs::StdRng::from_entropy();
            let mut data = BytesMut::with_capacity(settings.nonce_length);
            for _ in 0..settings.nonce_length {
                data.put_u8(rng.gen());
            }
            Some(SignatureNonce {
                data: data.freeze(),
            })
        } else {
            None
        };

        let seq_num = sign_method.next_seq_num();
        self.signature_info = Some(InterestSignatureInfo {
            signature_type: SignatureType {
                signature_type: T::SIGNATURE_TYPE.into(),
            },
            key_locator: sign_method.locator(),
            nonce,
            time: settings.include_time.then(|| sign_method.time()),
            seq_num: settings.include_seq_num.then(|| SignatureSeqNum {
                data: seq_num.into(),
            }),
        });

        let bytes = self.encode();
        let signature = {
            let mut bytes = bytes.clone();
            let _ = VarNum::decode(&mut bytes);
            let _ = VarNum::decode(&mut bytes);
            let _ = find_tlv::<ApplicationParameters>(&mut bytes, false);

            let mut signature_buffer =
                BytesMut::with_capacity(self.name.inner_size() + bytes.remaining());
            for component in &self.name.components {
                signature_buffer.put(component.encode());
            }
            signature_buffer.put(&mut bytes);

            sign_method.sign(signature_buffer.freeze())
        };

        let param_digest = {
            let mut data = bytes.clone();
            let _ = VarNum::decode(&mut data);
            let _ = VarNum::decode(&mut data);
            let _ = find_tlv::<ApplicationParameters>(&mut data, false);
            let mut hasher = Sha256::new();
            hasher.update(&data);
            hasher.update(&[0x2e]);
            hasher.update(VarNum::from(signature.len()).encode());
            hasher.update(signature.clone());
            hasher.finalize()
        };

        self.name
            .components
            .push(NameComponent::ParametersSha256DigestComponent(
                ParametersSha256DigestComponent {
                    name: param_digest.into(),
                },
            ));

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
            .set_interest_lifetime(Some(10_000u16.into()));

        assert_eq!(
            interest,
            Interest {
                name: Name::from_str("ndn:/hello/world").unwrap(),
                can_be_prefix: Some(CanBePrefix),
                must_be_fresh: None,
                forwarding_hint: None,
                nonce: None,
                interest_lifetime: Some(InterestLifetime {
                    lifetime: 10_000u16.into()
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
        let signed_interest = interest.sign(
            &mut signer,
            SignSettings {
                include_time: false,
                nonce_length: 0,
                include_seq_num: true,
            },
        );

        let name_components = [
            8, 5, b'h', b'e', b'l', b'l', b'o', 8, 5, b'w', b'o', b'r', b'l', b'd', //
        ];

        let app_params_plus = [
            36, 0, // ApplicationParameters
            44, 6, // SignatureInfo
            27, 1, 0, // Signature Type
            42, 1, 0, // seq num
        ];

        let mut hasher = Sha256::new();
        hasher.update(name_components);
        hasher.update(app_params_plus);
        let signature = hasher.finalize();

        hasher = Sha256::new();
        hasher.update(app_params_plus);
        hasher.update([46, 32]);
        hasher.update(signature);
        let param_digest = hasher.finalize();

        let mut full_record = Vec::new();
        full_record.extend([5, 94]);
        full_record.extend([7, 48]);
        full_record.extend(name_components);
        full_record.extend([2, 32]);
        full_record.extend(param_digest);
        full_record.extend(app_params_plus);
        full_record.extend([46, 32]);
        full_record.extend(signature);

        assert_eq!(<Vec<u8>>::from(signed_interest.encode()), full_record);
    }
}
