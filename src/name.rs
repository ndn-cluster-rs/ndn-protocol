use std::borrow::Cow;

use bytes::Bytes;
use ndn_tlv::{Tlv, TlvEncode};
use url::Url;

use crate::error::{NdnError, Result};

trait FromUriPart: Sized {
    fn from_uri_part(s: &[u8]) -> Option<Self>;
}

trait ToUriPart {
    fn to_uri_part(&self) -> String;
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(8)]
pub struct GenericNameComponent {
    name: Bytes,
}

impl FromUriPart for GenericNameComponent {
    fn from_uri_part(s: &[u8]) -> Option<Self> {
        let name = if s.starts_with(b"8=") {
            Bytes::copy_from_slice(&s[2..])
        } else {
            Bytes::copy_from_slice(s)
        };
        Some(Self { name })
    }
}

impl ToUriPart for GenericNameComponent {
    fn to_uri_part(&self) -> String {
        let name = if self.name.iter().all(|x| *x == b'.') {
            Bytes::from_iter(b"...".iter().chain(self.name.iter()).map(|x| *x))
        } else {
            self.name.clone()
        };
        urlencoding::encode_binary(&name).into_owned()
    }
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(1)]
pub struct ImplicitSha256DigestComponent {
    name: [u8; 32],
}

impl FromUriPart for ImplicitSha256DigestComponent {
    fn from_uri_part(s: &[u8]) -> Option<Self> {
        let mut name = [0; 32];
        if s.starts_with(b"sha256digest=") {
            hex::decode_to_slice(&s["sha256digest=".len()..], &mut name).ok()?;
        } else {
            assert!(s.starts_with(b"1="));
            name.clone_from_slice(&s[2..]);
        }
        Some(Self { name })
    }
}

impl ToUriPart for ImplicitSha256DigestComponent {
    fn to_uri_part(&self) -> String {
        format!("sha256digest={}", hex::encode(&self.name))
    }
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(2)]
pub struct ParametersSha256DigestComponent {
    pub(crate) name: [u8; 32],
}

impl FromUriPart for ParametersSha256DigestComponent {
    fn from_uri_part(s: &[u8]) -> Option<Self> {
        let mut name = [0; 32];
        if s.starts_with(b"params-sha256=") {
            hex::decode_to_slice(&s["params-sha256=".len()..], &mut name).ok()?;
        } else {
            assert!(s.starts_with(b"2="));
            name.clone_from_slice(&s[2..]);
        }
        Some(Self { name })
    }
}

impl ToUriPart for ParametersSha256DigestComponent {
    fn to_uri_part(&self) -> String {
        format!("params-sha256={}", hex::encode(&self.name))
    }
}

#[derive(Debug, Tlv, PartialEq, Eq)]
pub enum NameComponent {
    GenericNameComponent(GenericNameComponent),
    ImplicitSha256DigestComponent(ImplicitSha256DigestComponent),
    ParametersSha256DigestComponent(ParametersSha256DigestComponent),
}

impl FromUriPart for NameComponent {
    fn from_uri_part(segment: &[u8]) -> Option<Self> {
        if segment.starts_with(b"sha256digest=") {
            ImplicitSha256DigestComponent::from_uri_part(segment)
                .map(Self::ImplicitSha256DigestComponent)
        } else if segment.starts_with(b"params-sha256=") {
            ParametersSha256DigestComponent::from_uri_part(segment)
                .map(Self::ParametersSha256DigestComponent)
        } else {
            let expr = regex::bytes::Regex::new(r"^([0-9]+)=").expect("failed to compile regex");
            if let Some(captures) = expr.captures(segment) {
                let prefix: usize = String::from_utf8(captures.get(1).unwrap().as_bytes().to_vec())
                    .ok()?
                    .parse()
                    .ok()?;
                match prefix {
                    8 => {
                        GenericNameComponent::from_uri_part(segment).map(Self::GenericNameComponent)
                    }
                    1 => ImplicitSha256DigestComponent::from_uri_part(segment)
                        .map(Self::ImplicitSha256DigestComponent),
                    2 => ParametersSha256DigestComponent::from_uri_part(segment)
                        .map(Self::ParametersSha256DigestComponent),
                    _ => None,
                }
            } else {
                Some(NameComponent::GenericNameComponent(
                    GenericNameComponent::from_uri_part(segment)?,
                ))
            }
        }
    }
}

impl ToUriPart for NameComponent {
    fn to_uri_part(&self) -> String {
        match *self {
            Self::GenericNameComponent(ref component) => component.to_uri_part(),
            Self::ImplicitSha256DigestComponent(ref component) => component.to_uri_part(),
            Self::ParametersSha256DigestComponent(ref component) => component.to_uri_part(),
        }
    }
}

#[derive(Debug, Tlv, PartialEq, Eq)]
#[tlv(7)]
pub struct Name {
    pub(crate) components: Vec<NameComponent>,
}

impl Name {
    pub fn from_str(s: &str) -> Result<Self> {
        let s = if !s.starts_with("ndn:") {
            Cow::Owned(format!("ndn:{}", s))
        } else {
            Cow::Borrowed(s)
        };

        let uri = Url::parse(&s)?;
        let path = uri.path();

        let mut components = Vec::with_capacity(path.split("/").count());

        for mut segment in path.split("/") {
            if segment == "" {
                continue;
            }
            if segment.bytes().all(|x| x == b'.') {
                segment = &segment[3..];
            }
            let decoded = urlencoding::decode_binary(segment.as_bytes());
            components.push(NameComponent::from_uri_part(&decoded).ok_or(NdnError::ParseError)?);
        }

        Ok(Name { components })
    }

    pub fn to_uri(&self) -> Url {
        let path: String = itertools::intersperse(
            self.components
                .iter()
                .map(ToUriPart::to_uri_part)
                .map(Cow::Owned),
            Cow::Borrowed("/"),
        )
        .collect();
        Url::parse(&format!("ndn:/{}", path)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_name() {
        let uri = "/hello/world";
        let name = Name::from_str(uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    })
                ]
            }
        );
        assert_eq!(name.to_uri(), Url::parse("ndn:/hello/world").unwrap());
    }

    #[test]
    fn simple_name_with_schema() {
        let uri = "ndn:/hello/world";
        let name = Name::from_str(uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    })
                ]
            }
        );
        assert_eq!(name.to_uri(), Url::parse("ndn:/hello/world").unwrap());
    }

    #[test]
    fn name_with_digest() {
        let uri = "/hello/world/sha256digest=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let name = Name::from_str(uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    }),
                    NameComponent::ImplicitSha256DigestComponent(ImplicitSha256DigestComponent {
                        name: [
                            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                        ]
                    })
                ]
            }
        );
        assert_eq!(name.to_uri(), Url::parse(&format!("ndn:{}", uri)).unwrap());
    }

    #[test]
    fn name_with_digest_direct() {
        let uri = "/hello/world/1=%de%ad%be%ef%de%ad%be%ef%de%ad%be%ef%de%ad%be%ef%de%ad%be%ef%de%ad%be%ef%de%ad%be%ef%de%ad%be%ef";
        let name = Name::from_str(uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    }),
                    NameComponent::ImplicitSha256DigestComponent(ImplicitSha256DigestComponent {
                        name: [
                            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                        ]
                    })
                ]
            }
        );
    }

    #[test]
    fn name_with_params_sha256() {
        let uri = "/hello/world/params-sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let name = Name::from_str(uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    }),
                    NameComponent::ParametersSha256DigestComponent(
                        ParametersSha256DigestComponent {
                            name: [
                                0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE,
                                0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
                                0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                            ]
                        }
                    )
                ]
            }
        );
        assert_eq!(name.to_uri(), Url::parse(&format!("ndn:{}", uri)).unwrap());
    }

    #[test]
    fn name_with_params_sha256_direct() {
        let uri = "/hello/world/2=%de%ad%be%ef%de%ad%be%ef%de%ad%be%ef%de%ad%be%ef%de%ad%be%ef%de%ad%be%ef%de%ad%be%ef%de%ad%be%ef";
        let name = Name::from_str(uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    }),
                    NameComponent::ParametersSha256DigestComponent(
                        ParametersSha256DigestComponent {
                            name: [
                                0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE,
                                0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
                                0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                            ]
                        }
                    )
                ]
            }
        );
    }

    #[test]
    fn dot2() {
        let uri = "/hello/../world";
        let name = Name::from_str(uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![NameComponent::GenericNameComponent(GenericNameComponent {
                    name: Bytes::from(&b"world"[..])
                })]
            }
        );
    }

    #[test]
    fn dot3() {
        let uri = "/.../world";
        let name = Name::from_str(uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b""[..])
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    })
                ]
            }
        );
        assert_eq!(name.to_uri(), Url::parse(&format!("ndn:{}", uri)).unwrap());
    }

    #[test]
    fn dot4() {
        let uri = "/..../world";
        let name = Name::from_str(uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"."[..])
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    })
                ]
            }
        );
        assert_eq!(name.to_uri(), Url::parse(&format!("ndn:{}", uri)).unwrap());
    }
}
