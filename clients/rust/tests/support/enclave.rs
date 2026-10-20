//! Controlled enclave peer: the fixed public P-384 scalar 2 and Python-generated
//! descriptions in `fixtures/azure/enclave.json`. No attestation is involved.
#![allow(dead_code)]
use aws_lc_rs::{
    agreement::{self, ECDH_P384, PrivateKey, UnparsedPublicKey},
    digest::{SHA256, digest},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{sync::Arc, time::Duration};
use tds_client::{
    encryption::{self, KeyFuture, KeyOperation, KeyProvider, MasterKey, Plaintext, WrappedKey},
    packet,
    requests::decode,
};
pub fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../fixtures/azure/enclave.json")).unwrap()
}
pub fn bytes(f: &serde_json::Value, name: &str) -> Vec<u8> {
    STANDARD.decode(f[name].as_str().unwrap()).unwrap()
}
pub struct Root(pub [u8; 32]);
impl KeyProvider for Root {
    fn name(&self) -> &str {
        "peer"
    }
    fn open<'a>(&'a self, _: &'a str, _: KeyOperation) -> KeyFuture<'a, Arc<dyn MasterKey>> {
        Box::pin(async move { Ok(Arc::new(Root(self.0)) as Arc<dyn MasterKey>) })
    }
}
impl MasterKey for Root {
    fn unwrap<'a>(&'a self, _: &'a WrappedKey, _: KeyOperation) -> KeyFuture<'a, Plaintext> {
        Box::pin(async move { Plaintext::copy(&self.0) })
    }
    fn wrap<'a>(&'a self, _: &'a Plaintext, _: KeyOperation) -> KeyFuture<'a, Vec<u8>> {
        Box::pin(async { unreachable!() })
    }
    fn sign_metadata(&self, _: bool, _: KeyOperation) -> KeyFuture<'_, Vec<u8>> {
        Box::pin(async { unreachable!() })
    }
    fn verify_metadata<'a>(&'a self, _: bool, _: &'a [u8], _: KeyOperation) -> KeyFuture<'a, bool> {
        Box::pin(async { unreachable!() })
    }
}
/// A key session whose only "master key" returns `root`, for peer-side decryption.
pub fn peer_key(root: [u8; 32]) -> encryption::KeySession {
    encryption::KeySession::with_providers(
        vec![Arc::new(Root(root))],
        Default::default(),
        Duration::from_secs(2),
    )
    .unwrap()
}
pub fn root_from_parameters(parameters: &[u8]) -> [u8; 32] {
    assert_eq!(
        &parameters[..20],
        &[
            2, 0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, b'E', b'C', b'K', b'3', 48, 0, 0, 0
        ]
    );
    let mut seed = [0; 48];
    seed[47] = 2;
    let private = PrivateKey::from_private_key(&ECDH_P384, &seed).unwrap();
    let mut point = vec![4];
    point.extend(&parameters[20..]);
    agreement::agree(
        &private,
        UnparsedPublicKey::new(&ECDH_P384, point),
        (),
        |secret| Ok(digest(&SHA256, secret).as_ref().try_into().unwrap()),
    )
    .unwrap()
}
pub fn read_call(body: &[u8]) -> decode::Call {
    let decode::Request::Rpc { mut calls, .. } =
        decode::request_with_enclaves(packet::RPC, body, true).unwrap()
    else {
        panic!("RPC")
    };
    assert_eq!(calls.len(), 1);
    calls.remove(0)
}
