#![warn(missing_docs)]
//! Implements the core Named Data Networking (NDN) packet types -- [`Name`],
//! [`Interest`], [`Data`], signatures, and certificates -- on top of the TLV
//! encoding provided by [`ndn-tlv`](https://crates.io/crates/ndn-tlv).
//!
//! [`Name`] represents a hierarchical NDN name and can be built from a URI
//! with [`Name::from_str`]. [`Interest`] and [`Data`] are the two packet
//! types that make up NDN's request/response exchange; both are generic
//! over their payload type so application data can be encoded and decoded
//! through the same [`ndn_tlv::TlvEncode`]/[`ndn_tlv::TlvDecode`] traits
//! used everywhere else in the stack. Signing and verifying either packet
//! type goes through the [`SignMethod`](signature::SignMethod) and
//! [`SignatureVerifier`](signature::SignatureVerifier) traits, with
//! [`DigestSha256`] and [`SignatureSha256WithRsa`] as the two signature
//! schemes implemented here.
//!
//! ```rust
//! use ndn_protocol::{DigestSha256, Interest, Name, SignSettings};
//!
//! let mut interest = Interest::<()>::new(Name::from_str("/hello/world").unwrap());
//! let mut signer = DigestSha256::new();
//! interest.sign(&mut signer, SignSettings::default());
//! assert!(interest.verify(&signer).is_ok());
//! ```
//!
//! This crate implements the packet types themselves; it doesn't talk to a
//! forwarder. [`ndn-app`](https://crates.io/crates/ndn-app) builds an
//! application framework on top of these types.

pub use data::{Content, ContentType, Data, FinalBlockId, FreshnessPeriod, MetaInfo};
pub use interest::{
    CanBePrefix, ForwardingHint, HopLimit, Interest, InterestLifetime, MustBeFresh, Nonce,
    SignSettings,
};
pub use name::{
    GenericNameComponent, ImplicitSha256DigestComponent, Name, NameComponent, OtherNameComponent,
};
pub use signature::{
    DigestSha256, KeyDigest, KeyLocator, SignatureInfo, SignatureSha256WithRsa, SignatureType,
    SignatureValue,
};

pub use certificate::{Certificate, RsaCertificate, SafeBag};

pub mod certificate;
pub mod data;
pub mod error;
pub mod interest;
pub mod name;
pub mod signature;
