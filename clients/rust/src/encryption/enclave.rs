//! Python-compatible explicit no-attestation P-384 session and packages.
//! This mode trusts the SQL server's enclave; it does not verify attestation.
use super::{Error, Plaintext, Result, cell::Cell};
use aws_lc_rs::{
    agreement::{self, ECDH_P384, PrivateKey, UnparsedPublicKey},
    digest::{SHA256, digest},
};
use zeroize::Zeroizing;

pub(super) struct Attestation {
    private: PrivateKey,
    parameters: Vec<u8>,
}
impl Attestation {
    pub(super) fn new() -> Result<Self> {
        Self::from_private(PrivateKey::generate(&ECDH_P384).map_err(|_| Error::Worker)?)
    }
    fn from_private(private: PrivateKey) -> Result<Self> {
        let public = private.compute_public_key().map_err(|_| Error::Worker)?;
        let bytes = public.as_ref();
        if bytes.len() != 97 || bytes[0] != 4 {
            return Err(Error::InvalidMetadata);
        }
        let mut parameters = Vec::with_capacity(116);
        parameters.extend(2_u32.to_le_bytes());
        parameters.extend(0_u32.to_le_bytes());
        parameters.extend(104_u32.to_le_bytes());
        parameters.extend(b"ECK3");
        parameters.extend(48_u32.to_le_bytes());
        parameters.extend(&bytes[1..]);
        Ok(Self {
            private,
            parameters,
        })
    }
    pub(super) fn parameters(&self) -> &[u8] {
        &self.parameters
    }
    pub(super) fn establish(self, info: &[u8]) -> Result<Session> {
        if info.len() > 65_536 {
            return Err(Error::InvalidMetadata);
        }
        let u32_at = |at: usize| -> Result<usize> {
            Ok(u32::from_le_bytes(
                info.get(at..at + 4)
                    .ok_or(Error::InvalidMetadata)?
                    .try_into()
                    .unwrap(),
            ) as usize)
        };
        let at = 8_usize
            .checked_add(u32_at(0)?)
            .ok_or(Error::InvalidMetadata)?;
        if at.checked_add(16).is_none_or(|end| end > info.len()) {
            return Err(Error::InvalidMetadata);
        }
        let _secure = u32_at(4)?; // Python's none mode skips trusted data and ignores the declared secure/signature lengths.
        let handle = info
            .get(at..at + 8)
            .ok_or(Error::InvalidMetadata)?
            .try_into()
            .unwrap();
        let size = u32_at(at + 8)?;
        let _signature = u32_at(at + 12)?;
        let end = (at + 16)
            .checked_add(size)
            .ok_or(Error::InvalidMetadata)?
            .min(info.len());
        let blob = info.get(at + 16..end).ok_or(Error::InvalidMetadata)?;
        if blob.len() != 104 || &blob[..4] != b"ECK3" {
            return Err(Error::InvalidMetadata);
        }
        let mut point = [0_u8; 97];
        point[0] = 4;
        point[1..].copy_from_slice(&blob[8..]);
        let key = agreement::agree(
            &self.private,
            UnparsedPublicKey::new(&ECDH_P384, point),
            Error::Authentication,
            |secret| {
                let root = Zeroizing::new(digest(&SHA256, secret).as_ref().to_vec());
                Cell::derive(
                    &root,
                    #[cfg(test)]
                    &None,
                )
            },
        )?;
        Ok(Session {
            handle,
            key,
            counter: 0,
        })
    }
}
pub(super) struct ReleasedKey {
    pub database_id: u32,
    pub metadata_version: [u8; 8],
    pub key_id: u32,
    pub root: Plaintext,
}
pub(super) struct Session {
    handle: [u8; 8],
    key: Box<Cell>,
    counter: i64,
}
impl Session {
    pub(super) fn package(&mut self, statement: &str, keys: &[ReleasedKey]) -> Result<Vec<u8>> {
        let length = keys
            .len()
            .checked_mul(46)
            .and_then(|n| n.checked_add(56))
            .ok_or(Error::ValueTooLarge)?;
        if length > super::cell::MAX_VALUE
            || keys
                .iter()
                .any(|k| k.root.as_bytes().len() != 32 || k.key_id > u16::MAX.into())
        {
            return Err(Error::InvalidMetadata);
        }
        self.counter = self.counter.checked_add(1).ok_or(Error::Expired)?;
        let mut body = Zeroizing::new(Vec::with_capacity(length));
        let mut guid = [0; 16];
        aws_lc_rs::rand::fill(&mut guid).map_err(|_| Error::Worker)?;
        guid[7] = (guid[7] & 0x0f) | 0x40;
        guid[8] = (guid[8] & 0x3f) | 0x80; // UUID v4 bytes_le.
        body.extend(guid);
        body.extend(self.counter.to_le_bytes());
        let statement: Vec<u8> = statement
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        body.extend(digest(&SHA256, &statement).as_ref());
        for key in keys {
            body.extend(key.database_id.to_le_bytes());
            body.extend(key.metadata_version);
            body.extend((key.key_id as u16).to_le_bytes());
            body.extend(key.root.as_bytes());
        }
        let mut package = self.handle.to_vec();
        package.extend(self.key.encrypt(&body, true)?);
        Ok(package)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../../tests/fixtures/azure/enclave.json")).unwrap()
    }
    fn bytes(f: &serde_json::Value, name: &str) -> Vec<u8> {
        STANDARD.decode(f[name].as_str().unwrap()).unwrap()
    }
    fn fixed() -> Attestation {
        let mut seed = [0; 48];
        seed[47] = 1;
        Attestation::from_private(PrivateKey::from_private_key(&ECDH_P384, &seed).unwrap()).unwrap()
    }
    #[test]
    fn p384_session_and_packages_mutually_match_python() {
        let f = fixture();
        let attestation = fixed();
        assert_eq!(attestation.parameters(), bytes(&f, "parameters"));
        let mut session = attestation.establish(&bytes(&f, "info")).unwrap();
        let package = bytes(&f, "package");
        assert_eq!(
            session.key.decrypt(&package[8..]).unwrap().as_bytes(),
            bytes(&f, "plaintext")
        );
        let keys = [ReleasedKey {
            database_id: 5,
            metadata_version: *b"version1",
            key_id: 7,
            root: Plaintext::copy(&[3; 32]).unwrap(),
        }];
        let emitted = session
            .package(f["statement"].as_str().unwrap(), &keys)
            .unwrap();
        let body = session.key.decrypt(&emitted[8..]).unwrap();
        assert_eq!(&body.as_bytes()[16..], &bytes(&f, "plaintext")[16..]);
        assert_eq!(body.as_bytes()[7] >> 4, 4);
        assert_eq!(body.as_bytes()[8] >> 6, 2);
        let next = session.package("different SQL", &keys).unwrap();
        let next = session.key.decrypt(&next[8..]).unwrap();
        assert_eq!(
            i64::from_le_bytes(next.as_bytes()[16..24].try_into().unwrap()),
            2
        );
        assert_ne!(&next.as_bytes()[24..56], &body.as_bytes()[24..56]);
        if let Some(path) = std::env::var_os("TDS_ENCLAVE_OUTPUT") {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap();
            file.write_all(
                serde_json::to_string(&serde_json::json!({"package":STANDARD.encode(emitted)}))
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
        }
    }
    #[test]
    fn malformed_points_tampered_packages_and_counter_exhaustion_are_refused() {
        let f = fixture();
        let info = bytes(&f, "info");
        for end in 0..info.len() {
            assert!(fixed().establish(&info[..end]).is_err(), "{end}");
        }
        let mut bad = info.clone();
        bad[32] = 0;
        assert!(fixed().establish(&bad).is_err());
        let mut session = fixed().establish(&info).unwrap();
        let mut package = bytes(&f, "package");
        *package.last_mut().unwrap() ^= 1;
        assert!(matches!(
            session.key.decrypt(&package[8..]),
            Err(Error::Authentication)
        ));
        session.counter = i64::MAX;
        assert_eq!(session.package("SQL", &[]), Err(Error::Expired));
        // Python's none mode ignores blob's point-size field and signatures.
        let mut equivalent = info;
        equivalent[28..32].copy_from_slice(&0_u32.to_le_bytes());
        equivalent.extend([8; 17]);
        assert!(fixed().establish(&equivalent).is_ok());
    }
    /// Part B (B-6): channels share one session under its mutex (as the key
    /// bank holds it). Concurrent packages get distinct, contiguous counters.
    #[test]
    fn concurrent_packages_from_one_session_never_reuse_a_counter() {
        use std::sync::{Arc, Mutex};
        let f = fixture();
        let session = Arc::new(Mutex::new(fixed().establish(&bytes(&f, "info")).unwrap()));
        let packages: Vec<Vec<u8>> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| {
                    let session = session.clone();
                    scope.spawn(move || {
                        (0..25)
                            .map(|_| session.lock().unwrap().package("SQL", &[]).unwrap())
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            workers
                .into_iter()
                .flat_map(|w| w.join().unwrap())
                .collect()
        });
        let session = session.lock().unwrap();
        let mut counters: Vec<i64> = packages
            .iter()
            .map(|p| {
                let body = session.key.decrypt(&p[8..]).unwrap();
                i64::from_le_bytes(body.as_bytes()[16..24].try_into().unwrap())
            })
            .collect();
        counters.sort_unstable();
        assert_eq!(counters, (1..=200).collect::<Vec<_>>());
    }
    #[test]
    fn a_package_from_another_session_does_not_decrypt() {
        let f = fixture();
        let info = bytes(&f, "info");
        let mut ours = fixed().establish(&info).unwrap();
        let theirs = Attestation::new().unwrap().establish(&info).unwrap();
        let package = ours.package("SQL", &[]).unwrap();
        assert_eq!(&package[..8], b"session1");
        assert!(matches!(
            theirs.key.decrypt(&package[8..]),
            Err(Error::Authentication)
        ));
    }
}
