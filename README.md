# ndn-protocol

[![docs.rs](https://img.shields.io/docsrs/ndn-protocol)](https://docs.rs/ndn-protocol)
[![crates.io](https://img.shields.io/crates/v/ndn-protocol)](https://crates.io/crates/ndn-protocol)
[![license](https://img.shields.io/crates/l/ndn-protocol)](https://github.com/ndn-cluster-rs/ndn-protocol/blob/master/LICENSE)

Implements the core Named Data Networking (NDN) packet types -- names, Interests, Data, and signatures -- on top of [`ndn-tlv`](https://crates.io/crates/ndn-tlv).

It gives you typed, spec-compliant packet construction, signing, and verification.

## Installation

```
cargo add ndn-protocol
```

## Example

```rust
use bytes::Bytes;
use ndn_protocol::{Data, DigestSha256, Interest, Name, SignSettings};

fn main() {
    let name = Name::from_str("/hello/world").unwrap();
    let mut signer = DigestSha256::new();

    // Consumer side: build and sign an Interest.
    let mut interest = Interest::<()>::new(name.clone());
    interest.sign(&mut signer, SignSettings::default());
    assert!(interest.verify(&signer).is_ok());

    // Producer side: answer with a signed Data packet.
    let mut data = Data::new(name, Bytes::from_static(b"hello!"));
    data.sign(&mut signer);
    assert!(data.verify(&signer).is_ok());
}
```

## How it works

- **Names** (`Name`) are hierarchical and built from typed `NameComponent`s -- a plain segment, a version number, an embedded digest, and so on -- so components can't be constructed from the wrong kind of data. Parse one from a URI with `Name::from_str`, or build one component by component.
- **Interests and Data** (`Interest`, `Data`) are the two packet types NDN's request/response exchange is built from. Both are generic over their payload type, so application data is encoded and decoded through the same `TlvEncode`/`TlvDecode` traits used everywhere else in the stack, instead of forcing callers to work with raw bytes.
- **Signing and verification** go through the `SignMethod` and `SignatureVerifier` traits, implemented by `DigestSha256` (a plain digest, proving only that a packet wasn't corrupted in transit) and `SignatureSha256WithRsa` (RSA over SHA-256, for real authentication). The same traits are used on the consuming side, so verifying an incoming Data or Interest looks the same regardless of which scheme signed it.
- **Certificates** (`Certificate`, `RsaCertificate`) are signed Data packets carrying a public key. Load one together with its private key from a `.safebag` file exported by `ndnsec` with `RsaCertificate::from_safebag`.
- **Errors** are reported through `NdnError` for parsing and I/O, and the narrower `SignError`/`VerifyError` for the signing and verification paths specifically.

This crate implements the packet types themselves; it doesn't talk to a forwarder. See [`ndn-app`](https://crates.io/crates/ndn-app) for that.

## Related crates

- [`ndn-app`](https://crates.io/crates/ndn-app) is an application framework for building NDN producers and consumers, built on top of this crate plus `ndn-ndnlp` and `ndn-nfd-mgmt`.
- [`ndn-tlv`](https://crates.io/crates/ndn-tlv) provides the TLV encoding/decoding traits this crate's packet types are built on.
- [`ndn-ndnlp`](https://crates.io/crates/ndn-ndnlp) implements NDNLPv2, the link-layer protocol used to send these packets over a transport.
- [`ndn-nfd-mgmt`](https://crates.io/crates/ndn-nfd-mgmt) implements the NFD management protocol, used e.g. to register routes with a local forwarder.

## License

MIT

---

Produced as part of a Master's thesis in Computer Science.
