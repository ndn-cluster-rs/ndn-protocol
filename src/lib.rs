pub use interest::{
    CanBePrefix, ForwardingHint, HopLimit, Interest, InterestLifetime, MustBeFresh, Nonce,
};
pub use name::{GenericNameComponent, ImplicitSha256DigestComponent, Name, NameComponent};

mod error;
mod interest;
mod name;

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
