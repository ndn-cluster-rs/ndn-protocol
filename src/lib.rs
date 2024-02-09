pub use name::{GenericNameComponent, ImplicitSha256DigestComponent, Name, NameComponent};

mod error;
mod name;

// #[derive(Debug, Tlv)]
// #[tlv(33)]
// struct CanBePrefix;
//
// #[derive(Debug, Tlv)]
// #[tlv(18)]
// struct MustBeFresh;
//
// #[derive(Debug, Tlv)]
// #[tlv(30)]
// struct ForwardingHint {
//     name: Name,
// }
//
// #[derive(Debug, Tlv)]
// #[tlv(10)]
// struct Nonce {
//     nonce: Bytes,
// }
//
// #[derive(Debug, Tlv)]
// #[tlv(12)]
// struct InterestLifetime {
//     lifetime: VarNum,
// }
//
// #[derive(Debug, Tlv)]
// #[tlv(34)]
// struct HopLimit {
//     limit: Bytes,
// }
//
// #[derive(Debug, Tlv)]
// #[tlv(5)]
// struct Interest {
//     name: Name,
//     can_be_prefix: Option<CanBePrefix>,
//     must_be_fresh: Option<MustBeFresh>,
//     forwarding_hint: Option<ForwardingHint>,
//     nonce: Option<Nonce>,
//     interest_lifetime: Option<InterestLifetime>,
//     hop_limit: Option<HopLimit>,
// }
//
// #[derive(Debug, Tlv)]
// #[tlv(24)]
// struct ContentType {
//     content_type: VarNum,
// }
//
// #[derive(Debug, Tlv)]
// #[tlv(25)]
// struct FreshnessPeriod {
//     freshness_period: VarNum,
// }
//
// #[derive(Debug, Tlv)]
// #[tlv(26)]
// struct FinalBlockId {
//     final_block_id: NameComponent,
// }
//
// #[derive(Debug, Tlv)]
// #[tlv(21)]
// struct Content {
//     data: Bytes,
// }
//
// #[derive(Debug, Tlv)]
// #[tlv(20)]
// struct MetaInfo {
//     content_type: Option<ContentType>,
//     freshness_period: Option<FreshnessPeriod>,
//     final_block_id: Option<FinalBlockId>,
// }
//
// #[derive(Debug, Tlv)]
// #[tlv(27)]
// struct SignatureType {
//     signature_type: VarNum,
// }
//
// #[derive(Debug, Tlv)]
// #[tlv(29)]
// struct KeyDigest {
//     data: Bytes,
// }
//
// #[derive(Debug, Tlv)]
// enum KeyLocatorData {
//     Name(Name),
//     KeyDigest(KeyDigest),
// }
//
// #[derive(Debug, Tlv)]
// #[tlv(28)]
// struct KeyLocator {
//     locator: KeyLocatorData,
// }
//
// #[derive(Debug, Tlv)]
// #[tlv(22)]
// struct SignatureInfo {
//     signature_type: SignatureType,
//     key_locator: Option<KeyLocator>,
// }
//
// #[derive(Debug, Tlv)]
// #[tlv(23)]
// struct SignatureValue {
//     data: Bytes,
// }
//
// #[derive(Debug, Tlv)]
// #[tlv(6)]
// struct Data {
//     name: Name,
//     meta_info: Option<MetaInfo>,
//     content: Option<Content>,
//     signature_info: SignatureInfo,
//     signature_value: SignatureValue,
// }
