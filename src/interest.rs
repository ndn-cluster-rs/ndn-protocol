use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_more::{AsMut, AsRef, Constructor, From, Into};
use ndn_tlv::{find_tlv, NonNegativeInteger, Tlv, TlvDecode, TlvEncode, VarNum};
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};

use crate::{
    error::{SignError, VerifyError},
    name::ParametersSha256DigestComponent,
    signature::{
        InterestSignatureInfo, InterestSignatureValue, SignMethod, SignatureNonce, SignatureSeqNum,
    },
    Certificate, Name, NameComponent, SignatureType,
};

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Copy, Constructor, Hash, Default)]
#[tlv(33)]
pub struct CanBePrefix;

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Copy, Constructor, Hash, Default)]
#[tlv(18)]
pub struct MustBeFresh;

#[derive(Debug, Tlv, PartialEq, Eq, Clone, PartialOrd, Ord, Hash, Constructor)]
#[tlv(30)]
pub struct ForwardingHint {
    name: Name,
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Copy, Constructor, From, Into, AsRef, AsMut, Hash)]
#[tlv(10)]
pub struct Nonce {
    nonce: [u8; 4],
}

#[derive(
    Debug,
    Tlv,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Constructor,
    From,
    Into,
    AsRef,
    AsMut,
    Hash,
    PartialOrd,
    Ord,
)]
#[tlv(12)]
pub struct InterestLifetime {
    lifetime: NonNegativeInteger,
}

#[derive(
    Debug,
    Tlv,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Constructor,
    From,
    Into,
    AsRef,
    AsMut,
    Hash,
    PartialOrd,
    Ord,
)]
#[tlv(34)]
pub struct HopLimit {
    limit: u8,
}

#[derive(Debug, Tlv, PartialEq, Eq, Hash, From, AsRef, AsMut, Constructor, Clone)]
#[tlv(36)]
pub struct ApplicationParameters<T> {
    data: T,
}

#[derive(Debug, Tlv, PartialEq, Eq, Hash, Clone)]
#[tlv(5)]
pub struct Interest<T> {
    name: Name,
    can_be_prefix: Option<CanBePrefix>,
    must_be_fresh: Option<MustBeFresh>,
    forwarding_hint: Option<ForwardingHint>,
    nonce: Option<Nonce>,
    interest_lifetime: Option<InterestLifetime>,
    hop_limit: Option<HopLimit>,
    application_parameters: Option<ApplicationParameters<T>>,
    signature_info: Option<InterestSignatureInfo>,
    signature_value: Option<InterestSignatureValue>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Constructor, Hash)]
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

impl<AppParamTy> Interest<AppParamTy>
where
    AppParamTy: TlvEncode,
    AppParamTy: TlvDecode,
{
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
            signature_value: None,
        }
    }

    /// Creates the `ParametersSha256DigestComponent` part of the name.
    ///
    /// The component will be automatically added to the name when signing the interest, so this is
    /// only useful for unsigned interests.
    pub fn make_parameters_digest(data: AppParamTy) -> ParametersSha256DigestComponent {
        let mut hasher = Sha256::new();
        hasher.update(VarNum::from(ApplicationParameters::<AppParamTy>::TYP).encode());
        hasher.update(VarNum::from(data.size()).encode());
        hasher.update(&data.encode());
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
    pub fn add_parameters_digest(&mut self) -> &mut Self
    where
        AppParamTy: Default,
        AppParamTy: Clone,
    {
        if self.application_parameters.is_none() {
            self.application_parameters = Some(ApplicationParameters {
                data: AppParamTy::default(),
            });
        }

        self.add_parameters_digest_unchecked()
    }

    /// Adds a `ParametersSha256DigestComponent` to the end of the name, assuming application
    /// parameters already exist
    ///
    /// The component will be automatically added to the name when signing the interest, so this is
    /// only useful for unsigned interests.
    ///
    /// Any existing `ParametersSha256DigestComponent` will be removed.
    pub fn add_parameters_digest_unchecked(&mut self) -> &mut Self
    where
        AppParamTy: Clone,
    {
        self.name
            .components
            .retain(|x| !matches!(x, NameComponent::ParametersSha256DigestComponent(_)));

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

    pub fn set_application_parameters(&mut self, params: Option<AppParamTy>) -> &mut Self {
        self.application_parameters = params.map(|data| ApplicationParameters { data });
        self
    }

    pub fn application_parameters(&self) -> Option<&AppParamTy> {
        self.application_parameters.as_ref().map(|x| &x.data)
    }

    fn signable_portion(&self) -> Bytes {
        let mut bytes = self.encode();
        let _ = VarNum::decode(&mut bytes);
        let _ = VarNum::decode(&mut bytes);
        let _ = find_tlv::<ApplicationParameters<AppParamTy>>(&mut bytes, false);

        let mut end = bytes.clone();
        let _ = find_tlv::<InterestSignatureValue>(&mut end, false);
        bytes.truncate(bytes.remaining() - end.remaining());

        let mut signature_buffer =
            BytesMut::with_capacity(self.name.inner_size() + bytes.remaining());
        for component in &self.name.components {
            if !matches!(component, NameComponent::ParametersSha256DigestComponent(_)) {
                signature_buffer.put(component.encode());
            }
        }
        signature_buffer.put(&mut bytes);
        signature_buffer.freeze()
    }

    fn parameters_digest(&self) -> [u8; 32] {
        let mut data = self.encode();
        let _ = VarNum::decode(&mut data);
        let _ = VarNum::decode(&mut data);
        let _ = find_tlv::<ApplicationParameters<AppParamTy>>(&mut data, false);
        let mut hasher = Sha256::new();
        hasher.update(&data);
        hasher.finalize().into()
    }

    pub fn sign<T>(&mut self, sign_method: &mut T, settings: SignSettings)
    where
        T: SignMethod,
        AppParamTy: Default,
    {
        if self.application_parameters.is_none() {
            self.set_application_parameters(Some(AppParamTy::default()));
        }

        self.sign_checked(sign_method, settings)
            .expect("sign_checked failed from sign")
    }

    pub fn sign_checked<T>(
        &mut self,
        sign_method: &mut T,
        settings: SignSettings,
    ) -> Result<(), SignError>
    where
        T: SignMethod,
    {
        // Delete existing params-sha256
        self.name
            .components
            .retain(|x| !matches!(x, NameComponent::ParametersSha256DigestComponent(_)));
        if self.application_parameters.is_none() {
            return Err(SignError::MissingApplicationParameters);
        }

        // Generate nonce
        let nonce = if settings.nonce_length > 0 {
            let mut rng = rand::rngs::StdRng::from_entropy();
            let mut data = BytesMut::with_capacity(settings.nonce_length);
            for _ in 0..settings.nonce_length {
                data.put_u8(rng.gen());
            }
            Some(SignatureNonce::new(data.freeze()))
        } else {
            None
        };

        // Generate sequence number
        let seq_num = sign_method.next_seq_num();

        self.signature_info = Some(InterestSignatureInfo {
            signature_type: SignatureType::new(T::SIGNATURE_TYPE.into()),
            key_locator: sign_method.certificate().locator(),
            nonce,
            time: settings.include_time.then(|| sign_method.time()),
            seq_num: settings
                .include_seq_num
                .then(|| SignatureSeqNum::new(seq_num.into())),
        });

        // Create signature
        self.signature_value = Some(InterestSignatureValue::new(
            sign_method.sign(&self.signable_portion()),
        ));

        // Add new params-sha256
        self.name
            .components
            .push(NameComponent::ParametersSha256DigestComponent(
                ParametersSha256DigestComponent {
                    name: self.parameters_digest(),
                },
            ));
        Ok(())
    }

    pub fn is_signed(&self) -> bool {
        self.signature_info.is_some()
    }

    fn verify_param_digest(&self) -> Result<(), VerifyError> {
        if self.is_signed() {
            if self.application_parameters.is_none() {
                return Err(VerifyError::MissingApplicationParameters);
            }

            let Some(NameComponent::ParametersSha256DigestComponent(param_digest)) =
                self.name.components.last()
            else {
                return Err(VerifyError::InvalidParameterDigest);
            };

            if param_digest.name != self.parameters_digest() {
                return Err(VerifyError::InvalidParameterDigest);
            }
            Ok(())
        } else {
            if self.application_parameters.is_some() {
                // Not signed, application parameters present - check parameter digest
                for component in &self.name.components {
                    if let NameComponent::ParametersSha256DigestComponent(component) = component {
                        if component.name == self.parameters_digest() {
                            return Ok(());
                        } else {
                            return Err(VerifyError::InvalidParameterDigest);
                        }
                    }
                }
                // No digest present
                Err(VerifyError::InvalidParameterDigest)
            } else {
                // Not signed, no application parameters - nothing to check
                Ok(())
            }
        }
    }

    /// Verify the interest with a given sign method
    ///
    /// Returns `Ok(())` if the signature and the `ParametersSha256DigestComponent` of the name are
    /// valid
    pub fn verify_with_sign_method<T>(
        &self,
        sign_method: &T,
        cert: T::Certificate,
    ) -> Result<(), VerifyError>
    where
        T: SignMethod,
    {
        self.verify_param_digest()?;

        if self.signature_info.is_none() {
            // Not signed
            return Ok(());
        }

        let Some(ref sig_value) = self.signature_value else {
            // Signature missing
            return Err(VerifyError::InvalidSignature);
        };

        sign_method
            .verify(&self.signable_portion(), cert, sig_value.as_ref())
            .then_some(())
            .ok_or(VerifyError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use crate::signature::DigestSha256;

    use super::*;

    #[test]
    fn simple_usage() {
        let mut interest = Interest::<()>::new(Name::from_str("ndn:/hello/world").unwrap());
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
                signature_value: None,
            }
        );
    }

    #[test]
    fn sha256_interest() {
        let mut interest = Interest::<()>::new(Name::from_str("ndn:/hello/world").unwrap());
        let mut signer = DigestSha256::new();
        interest.sign(
            &mut signer,
            SignSettings {
                include_time: false,
                nonce_length: 0,
                include_seq_num: true,
            },
        );
        assert!(interest.verify_with_sign_method(&mut signer, ()).is_ok());

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

        assert_eq!(<Vec<u8>>::from(interest.encode()), full_record);
    }
}
