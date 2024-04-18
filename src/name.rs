use std::{
    borrow::Cow,
    cmp::max,
    time::{Duration, SystemTime},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_more::{AsMut, AsRef, Display, From, Into};
use ndn_tlv::{NonNegativeInteger, Tlv, TlvDecode, TlvEncode, VarNum};
use url::Url;

use crate::error::{NdnError, Result};

trait FromUriPart: Sized {
    fn from_uri_part(s: &[u8]) -> Option<Self>;
}

trait ToUriPart {
    fn to_uri_part(&self) -> String;
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, From, Into, AsRef, AsMut)]
#[tlv(8)]
pub struct GenericNameComponent {
    pub name: Bytes,
}

impl GenericNameComponent {
    pub fn new(name: Bytes) -> Self {
        Self { name }
    }
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

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, From, Into, AsRef, AsMut)]
#[tlv(32)]
pub struct KeywordNameComponent {
    pub name: Bytes,
}

impl KeywordNameComponent {
    pub fn new(name: Bytes) -> Self {
        Self { name }
    }
}

impl FromUriPart for KeywordNameComponent {
    fn from_uri_part(s: &[u8]) -> Option<Self> {
        let name = if s.starts_with(b"32=") {
            Bytes::copy_from_slice(&s[3..])
        } else {
            return None;
        };
        Some(Self { name })
    }
}

impl ToUriPart for KeywordNameComponent {
    fn to_uri_part(&self) -> String {
        format!("32={}", urlencoding::encode_binary(&self.name))
    }
}

#[derive(
    Debug,
    Tlv,
    PartialEq,
    Eq,
    Clone,
    Hash,
    Default,
    PartialOrd,
    Ord,
    From,
    Into,
    AsRef,
    AsMut,
    Display,
)]
#[tlv(50)]
pub struct SegmentNameComponent {
    pub segment_number: NonNegativeInteger,
}

impl SegmentNameComponent {
    pub fn new(segment_number: NonNegativeInteger) -> Self {
        Self { segment_number }
    }
}

impl From<u64> for SegmentNameComponent {
    fn from(value: u64) -> Self {
        Self::new(NonNegativeInteger::new(value))
    }
}

impl From<usize> for SegmentNameComponent {
    fn from(value: usize) -> Self {
        Self::new(NonNegativeInteger::new(value as u64))
    }
}

impl FromUriPart for SegmentNameComponent {
    fn from_uri_part(s: &[u8]) -> Option<Self> {
        let name = if s.starts_with(b"50=") {
            let mut buf = [0; std::mem::size_of::<u64>()];
            let slice = &s[3..];

            let start_idx = max(0, buf.len() - slice.len());
            for i in start_idx..buf.len() {
                buf[i] = slice[i - start_idx];
            }

            NonNegativeInteger::new(u64::from_be_bytes(buf))
        } else if s.starts_with(b"seg=") {
            let number = std::str::from_utf8(&s[4..]).ok()?.parse::<u64>().ok()?;
            NonNegativeInteger::new(number)
        } else {
            return None;
        };
        Some(Self {
            segment_number: name,
        })
    }
}

impl ToUriPart for SegmentNameComponent {
    fn to_uri_part(&self) -> String {
        format!("seg={}", self.segment_number)
    }
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
    Default,
    From,
    Into,
    AsRef,
    AsMut,
    Display,
)]
#[tlv(52)]
pub struct ByteOffsetNameComponent {
    pub offset: NonNegativeInteger,
}

impl ByteOffsetNameComponent {
    pub fn new(offset: NonNegativeInteger) -> Self {
        Self { offset }
    }
}

impl From<u64> for ByteOffsetNameComponent {
    fn from(value: u64) -> Self {
        Self::new(NonNegativeInteger::new(value))
    }
}

impl From<usize> for ByteOffsetNameComponent {
    fn from(value: usize) -> Self {
        Self::new(NonNegativeInteger::new(value as u64))
    }
}

impl FromUriPart for ByteOffsetNameComponent {
    fn from_uri_part(s: &[u8]) -> Option<Self> {
        let name = if s.starts_with(b"52=") {
            let mut buf = [0; std::mem::size_of::<u64>()];
            let slice = &s[3..];

            let start_idx = max(0, buf.len() - slice.len());
            for i in start_idx..buf.len() {
                buf[i] = slice[i - start_idx];
            }

            NonNegativeInteger::new(u64::from_be_bytes(buf))
        } else if s.starts_with(b"off=") {
            let number = std::str::from_utf8(&s[4..]).ok()?.parse::<u64>().ok()?;
            NonNegativeInteger::new(number)
        } else {
            return None;
        };
        Some(Self { offset: name })
    }
}

impl ToUriPart for ByteOffsetNameComponent {
    fn to_uri_part(&self) -> String {
        format!("off={}", self.offset)
    }
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
    Default,
    From,
    Into,
    AsRef,
    AsMut,
    Display,
)]
#[tlv(54)]
pub struct VersionNameComponent {
    pub version: NonNegativeInteger,
}

impl VersionNameComponent {
    pub fn new(version: NonNegativeInteger) -> Self {
        Self { version }
    }
}

impl From<u64> for VersionNameComponent {
    fn from(value: u64) -> Self {
        Self::new(NonNegativeInteger::new(value))
    }
}

impl From<usize> for VersionNameComponent {
    fn from(value: usize) -> Self {
        Self::new(NonNegativeInteger::new(value as u64))
    }
}

impl FromUriPart for VersionNameComponent {
    fn from_uri_part(s: &[u8]) -> Option<Self> {
        let name = if s.starts_with(b"54=") {
            let mut buf = [0; std::mem::size_of::<u64>()];
            let slice = &s[3..];

            let start_idx = max(0, buf.len() - slice.len());
            for i in start_idx..buf.len() {
                buf[i] = slice[i - start_idx];
            }

            NonNegativeInteger::new(u64::from_be_bytes(buf))
        } else if s.starts_with(b"v=") {
            let number = std::str::from_utf8(&s[2..]).ok()?.parse::<u64>().ok()?;
            NonNegativeInteger::new(number)
        } else {
            return None;
        };
        Some(Self { version: name })
    }
}

impl ToUriPart for VersionNameComponent {
    fn to_uri_part(&self) -> String {
        format!("v={}", self.version)
    }
}

#[derive(
    Debug, Tlv, PartialEq, Eq, Clone, PartialOrd, Ord, Hash, From, Into, AsRef, AsMut, Display,
)]
#[tlv(56)]
pub struct TimestampNameComponent {
    pub time: NonNegativeInteger,
}

impl TimestampNameComponent {
    pub fn new(time: NonNegativeInteger) -> Self {
        Self { time }
    }

    pub fn now() -> Self {
        Self::new(NonNegativeInteger::new(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_millis() as u64,
        ))
    }
}

impl Default for TimestampNameComponent {
    fn default() -> Self {
        Self::now()
    }
}

impl From<u64> for TimestampNameComponent {
    fn from(value: u64) -> Self {
        Self::new(NonNegativeInteger::new(value))
    }
}

impl From<usize> for TimestampNameComponent {
    fn from(value: usize) -> Self {
        Self::new(NonNegativeInteger::new(value as u64))
    }
}

impl FromUriPart for TimestampNameComponent {
    fn from_uri_part(s: &[u8]) -> Option<Self> {
        let name = if s.starts_with(b"56=") {
            let mut buf = [0; std::mem::size_of::<u64>()];
            let slice = &s[3..];

            let start_idx = max(0, buf.len() - slice.len());
            for i in start_idx..buf.len() {
                buf[i] = slice[i - start_idx];
            }

            NonNegativeInteger::new(u64::from_be_bytes(buf))
        } else if s.starts_with(b"t=") {
            let number = std::str::from_utf8(&s[2..]).ok()?.parse::<u64>().ok()?;
            NonNegativeInteger::new(number)
        } else {
            return None;
        };
        Some(Self { time: name })
    }
}

impl ToUriPart for TimestampNameComponent {
    fn to_uri_part(&self) -> String {
        format!("t={}", self.time)
    }
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
    Default,
    From,
    Into,
    AsRef,
    AsMut,
    Display,
)]
#[tlv(58)]
pub struct SequenceNumNameComponent {
    pub sequence_number: NonNegativeInteger,
}

impl SequenceNumNameComponent {
    pub fn new(sequence_number: NonNegativeInteger) -> Self {
        Self { sequence_number }
    }
}

impl From<u64> for SequenceNumNameComponent {
    fn from(value: u64) -> Self {
        Self::new(NonNegativeInteger::new(value))
    }
}

impl From<usize> for SequenceNumNameComponent {
    fn from(value: usize) -> Self {
        Self::new(NonNegativeInteger::new(value as u64))
    }
}

impl FromUriPart for SequenceNumNameComponent {
    fn from_uri_part(s: &[u8]) -> Option<Self> {
        let name = if s.starts_with(b"58=") {
            let mut buf = [0; std::mem::size_of::<u64>()];
            let slice = &s[3..];

            let start_idx = max(0, buf.len() - slice.len());
            for i in start_idx..buf.len() {
                buf[i] = slice[i - start_idx];
            }

            NonNegativeInteger::new(u64::from_be_bytes(buf))
        } else if s.starts_with(b"seq=") {
            let number = std::str::from_utf8(&s[4..]).ok()?.parse::<u64>().ok()?;
            NonNegativeInteger::new(number)
        } else {
            return None;
        };
        Some(Self {
            sequence_number: name,
        })
    }
}

impl ToUriPart for SequenceNumNameComponent {
    fn to_uri_part(&self) -> String {
        format!("seq={}", self.sequence_number)
    }
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, From, Into, AsRef, AsMut)]
#[tlv(1)]
pub struct ImplicitSha256DigestComponent {
    pub(crate) name: [u8; 32],
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

impl std::fmt::Display for ImplicitSha256DigestComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "{}", hex::encode_upper(self.name))
        } else {
            write!(f, "{}", hex::encode(self.name))
        }
    }
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash, From, Into, AsRef, AsMut)]
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

impl std::fmt::Display for ParametersSha256DigestComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "{}", hex::encode_upper(self.name))
        } else {
            write!(f, "{}", hex::encode(self.name))
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct OtherNameComponent {
    pub typ: VarNum,
    pub length: VarNum,
    pub data: Bytes,
}

impl FromUriPart for OtherNameComponent {
    fn from_uri_part(segment: &[u8]) -> Option<OtherNameComponent> {
        let (start, end) = segment.split_at(segment.partition_point(|x| *x == b'='));
        let typ = std::str::from_utf8(&start[..start.len() - 1]).ok()?;
        let length = end.len();

        let mut buf = BytesMut::with_capacity(length);
        buf.put(&end[..]);

        Some(OtherNameComponent {
            typ: VarNum::from(typ.parse::<u64>().ok()?),
            length: VarNum::from(length),
            data: buf.freeze(),
        })
    }
}

impl TlvEncode for OtherNameComponent {
    fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.size());
        buf.put(self.typ.encode());
        buf.put(self.length.encode());
        buf.put(self.data.encode());
        buf.freeze()
    }

    fn size(&self) -> usize {
        self.typ.size() + self.length.size() + self.data.len()
    }
}

impl TlvDecode for OtherNameComponent {
    fn decode(bytes: &mut Bytes) -> ndn_tlv::Result<Self> {
        let typ = VarNum::decode(bytes)?;
        let length = VarNum::decode(bytes)?;

        if bytes.remaining() < length.into() {
            return Err(ndn_tlv::TlvError::UnexpectedEndOfStream);
        }

        let mut buf = BytesMut::with_capacity(length.into());
        bytes.copy_to_slice(&mut buf);
        Ok(Self {
            typ,
            length,
            data: buf.freeze(),
        })
    }
}

impl ToUriPart for OtherNameComponent {
    fn to_uri_part(&self) -> String {
        format!(
            "{}={}",
            self.typ.value(),
            urlencoding::encode_binary(&self.data)
        )
    }
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, From, Hash)]
pub enum NameComponent {
    GenericNameComponent(GenericNameComponent),
    ImplicitSha256DigestComponent(ImplicitSha256DigestComponent),
    ParametersSha256DigestComponent(ParametersSha256DigestComponent),
    KeywordNameComponent(KeywordNameComponent),
    SegmentNameComponent(SegmentNameComponent),
    ByteOffsetNameComponent(ByteOffsetNameComponent),
    VersionNameComponent(VersionNameComponent),
    TimestampNameComponent(TimestampNameComponent),
    SequenceNumNameComponent(SequenceNumNameComponent),
    #[tlv(default)]
    OtherNameComponent(OtherNameComponent),
}

impl PartialOrd for NameComponent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NameComponent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let mut self_repr = self.encode();
        let mut other_repr = other.encode();

        while self_repr.has_remaining() && other_repr.has_remaining() {
            let self_cur = self_repr.get_u8();
            let other_cur = other_repr.get_u8();

            if self_cur < other_cur {
                return std::cmp::Ordering::Less;
            } else if self_cur > other_cur {
                return std::cmp::Ordering::Greater;
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl FromUriPart for NameComponent {
    fn from_uri_part(segment: &[u8]) -> Option<Self> {
        if segment.starts_with(b"sha256digest=") {
            ImplicitSha256DigestComponent::from_uri_part(segment)
                .map(Self::ImplicitSha256DigestComponent)
        } else if segment.starts_with(b"params-sha256=") {
            ParametersSha256DigestComponent::from_uri_part(segment)
                .map(Self::ParametersSha256DigestComponent)
        } else if segment.starts_with(b"seg=") {
            SegmentNameComponent::from_uri_part(segment).map(Self::SegmentNameComponent)
        } else if segment.starts_with(b"off=") {
            ByteOffsetNameComponent::from_uri_part(segment).map(Self::ByteOffsetNameComponent)
        } else if segment.starts_with(b"v=") {
            VersionNameComponent::from_uri_part(segment).map(Self::VersionNameComponent)
        } else if segment.starts_with(b"t=") {
            TimestampNameComponent::from_uri_part(segment).map(Self::TimestampNameComponent)
        } else if segment.starts_with(b"seq=") {
            SequenceNumNameComponent::from_uri_part(segment).map(Self::SequenceNumNameComponent)
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
                    32 => {
                        KeywordNameComponent::from_uri_part(segment).map(Self::KeywordNameComponent)
                    }
                    50 => {
                        SegmentNameComponent::from_uri_part(segment).map(Self::SegmentNameComponent)
                    }
                    52 => ByteOffsetNameComponent::from_uri_part(segment)
                        .map(Self::ByteOffsetNameComponent),
                    54 => {
                        VersionNameComponent::from_uri_part(segment).map(Self::VersionNameComponent)
                    }
                    56 => TimestampNameComponent::from_uri_part(segment)
                        .map(Self::TimestampNameComponent),
                    58 => SequenceNumNameComponent::from_uri_part(segment)
                        .map(Self::SequenceNumNameComponent),
                    _ => OtherNameComponent::from_uri_part(segment).map(Self::OtherNameComponent),
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
            Self::KeywordNameComponent(ref component) => component.to_uri_part(),
            Self::SegmentNameComponent(ref component) => component.to_uri_part(),
            Self::ByteOffsetNameComponent(ref component) => component.to_uri_part(),
            Self::VersionNameComponent(ref component) => component.to_uri_part(),
            Self::TimestampNameComponent(ref component) => component.to_uri_part(),
            Self::SequenceNumNameComponent(ref component) => component.to_uri_part(),
            Self::OtherNameComponent(ref component) => component.to_uri_part(),
        }
    }
}

#[derive(Debug, Tlv, PartialEq, Eq, Clone, Hash)]
#[tlv(7)]
pub struct Name {
    pub components: Vec<NameComponent>,
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Name {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let mut self_repr = self.encode();
        let mut other_repr = other.encode();

        while self_repr.has_remaining() && other_repr.has_remaining() {
            let self_cur = self_repr.get_u8();
            let other_cur = other_repr.get_u8();

            if self_cur < other_cur {
                return std::cmp::Ordering::Less;
            } else if self_cur > other_cur {
                return std::cmp::Ordering::Greater;
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl Name {
    pub const fn empty() -> Self {
        Name {
            components: Vec::new(),
        }
    }

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

    pub fn iter(&self) -> impl Iterator<Item = &NameComponent> {
        self.components.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut NameComponent> {
        self.components.iter_mut()
    }

    pub fn into_iter(self) -> impl Iterator<Item = NameComponent> {
        self.components.into_iter()
    }

    pub fn join<T: TryInto<Self>>(&self, other: T) -> Self
    where
        <T as TryInto<Self>>::Error: std::fmt::Debug,
    {
        let other = other.try_into().expect("Invalid name component string");

        let mut components = Vec::with_capacity(self.components.len() + other.components.len());
        components.extend_from_slice(&self.components);
        components.extend_from_slice(&other.components);
        Self { components }
    }

    pub fn has_prefix(&self, prefix: &Name) -> bool {
        if prefix.components.len() > self.components.len() {
            return false;
        }
        for (s, p) in self.components.iter().zip(prefix.iter()) {
            if s != p {
                return false;
            }
        }
        true
    }

    pub fn remove_prefix(&mut self, prefix: &Name) -> bool {
        if !self.has_prefix(prefix) {
            return false;
        }

        for _ in 0..prefix.components.len() {
            self.components.remove(0);
        }
        true
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_uri().fmt(f)
    }
}

impl From<NameComponent> for Name {
    fn from(value: NameComponent) -> Self {
        Name {
            components: vec![value],
        }
    }
}

impl TryFrom<&str> for Name {
    type Error = NdnError;

    fn try_from(value: &str) -> std::result::Result<Name, NdnError> {
        Name::from_str(value)
    }
}

impl FromIterator<NameComponent> for Name {
    fn from_iter<T: IntoIterator<Item = NameComponent>>(iter: T) -> Self {
        Self {
            components: iter.into_iter().collect(),
        }
    }
}

impl Extend<NameComponent> for Name {
    fn extend<T: IntoIterator<Item = NameComponent>>(&mut self, iter: T) {
        self.components.extend(iter)
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

    #[test]
    fn name_join_name() {
        let name = Name::from_str("/hello").unwrap();
        let name2 = Name::from_str("/world").unwrap();
        assert_eq!(name.join(name2), Name::from_str("/hello/world").unwrap());
    }

    #[test]
    fn name_join_component() {
        let name = Name::from_str("/hello").unwrap();
        let component = NameComponent::from_uri_part(b"world").unwrap();
        assert_eq!(
            name.join(component),
            Name::from_str("/hello/world").unwrap()
        );
    }

    #[test]
    fn name_slash_str() {
        let name = Name::from_str("/hello").unwrap();
        assert_eq!(name.join("world"), Name::from_str("/hello/world").unwrap());
    }

    #[test]
    fn name_keyword() {
        let uri = "ndn:/hello/32=PA/world";
        let name = Name::from_str(&uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::KeywordNameComponent(KeywordNameComponent {
                        name: Bytes::from(&b"PA"[..])
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    }),
                ]
            }
        );

        assert_eq!(name.to_uri(), Url::parse(&uri).unwrap());
    }

    #[test]
    fn name_segment() {
        let uri = "ndn:/hello/seg=5/world";
        let name = Name::from_str(&uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::SegmentNameComponent(SegmentNameComponent {
                        segment_number: NonNegativeInteger::U8(5)
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    }),
                ]
            }
        );

        assert_eq!(name.to_uri(), Url::parse(&uri).unwrap());
    }

    #[test]
    fn name_segment_binary() {
        let uri = "ndn:/hello/50=%05/world";
        let name = Name::from_str(&uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::SegmentNameComponent(SegmentNameComponent {
                        segment_number: NonNegativeInteger::U8(5)
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    }),
                ]
            }
        );
    }

    #[test]
    fn name_offset() {
        let uri = "ndn:/hello/off=5/world";
        let name = Name::from_str(&uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::ByteOffsetNameComponent(ByteOffsetNameComponent {
                        offset: NonNegativeInteger::U8(5)
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    }),
                ]
            }
        );

        assert_eq!(name.to_uri(), Url::parse(&uri).unwrap());
    }

    #[test]
    fn name_offset_binary() {
        let uri = "ndn:/hello/52=%05/world";
        let name = Name::from_str(&uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::ByteOffsetNameComponent(ByteOffsetNameComponent {
                        offset: NonNegativeInteger::U8(5)
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    }),
                ]
            }
        );
    }

    #[test]
    fn name_version() {
        let uri = "ndn:/hello/v=5/world";
        let name = Name::from_str(&uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::VersionNameComponent(VersionNameComponent {
                        version: NonNegativeInteger::U8(5)
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    }),
                ]
            }
        );

        assert_eq!(name.to_uri(), Url::parse(&uri).unwrap());
    }

    #[test]
    fn name_version_binary() {
        let uri = "ndn:/hello/54=%05/world";
        let name = Name::from_str(&uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::VersionNameComponent(VersionNameComponent {
                        version: NonNegativeInteger::U8(5)
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    }),
                ]
            }
        );
    }

    #[test]
    fn name_timestamp() {
        let uri = "ndn:/hello/t=5/world";
        let name = Name::from_str(&uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::TimestampNameComponent(TimestampNameComponent {
                        time: NonNegativeInteger::U8(5)
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    }),
                ]
            }
        );

        assert_eq!(name.to_uri(), Url::parse(&uri).unwrap());
    }

    #[test]
    fn name_timestamp_binary() {
        let uri = "ndn:/hello/56=%05/world";
        let name = Name::from_str(&uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::TimestampNameComponent(TimestampNameComponent {
                        time: NonNegativeInteger::U8(5)
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    }),
                ]
            }
        );
    }

    #[test]
    fn name_sequence_num() {
        let uri = "ndn:/hello/seq=5/world";
        let name = Name::from_str(&uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::SequenceNumNameComponent(SequenceNumNameComponent {
                        sequence_number: NonNegativeInteger::U8(5)
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    }),
                ]
            }
        );

        assert_eq!(name.to_uri(), Url::parse(&uri).unwrap());
    }

    #[test]
    fn name_sequence_num_binary() {
        let uri = "ndn:/hello/58=%05/world";
        let name = Name::from_str(&uri).unwrap();
        assert_eq!(
            name,
            Name {
                components: vec![
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"hello"[..])
                    }),
                    NameComponent::SequenceNumNameComponent(SequenceNumNameComponent {
                        sequence_number: NonNegativeInteger::U8(5)
                    }),
                    NameComponent::GenericNameComponent(GenericNameComponent {
                        name: Bytes::from(&b"world"[..])
                    }),
                ]
            }
        );
    }

    #[test]
    fn name_order() {
        let mut names = [
            Name::from_str("ndn:/some/prefix/name/fgh").unwrap(),
            Name::from_str("ndn:/some/prefix/name/asd").unwrap(),
            Name::from_str("ndn:/some/prefix/name/sha256digest=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap(),
            Name::from_str("ndn:/some/prefix").unwrap(),
        ];
        names.sort();
        assert_eq!(names, [
            Name::from_str("ndn:/some/prefix").unwrap(),
            Name::from_str("ndn:/some/prefix/name/asd").unwrap(),
            Name::from_str("ndn:/some/prefix/name/fgh").unwrap(),
            Name::from_str("ndn:/some/prefix/name/sha256digest=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap(),
        ]);
    }
}
