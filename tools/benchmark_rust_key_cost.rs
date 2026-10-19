//! Candidate primitive probe, not driver encryption or a full erasure audit.
//! Fixtures come from benchmark_encryption_cost.py --rust-probe <this binary>.
//! Compile optimized with aws-lc-rs 1.18.2 and zeroize 1.9.1 built rlibs.
use aws_lc_rs::{
    cipher::{
        DecryptionContext, EncryptionContext, PaddedBlockDecryptingKey, PaddedBlockEncryptingKey,
        UnboundCipherKey, AES_256,
    },
    hmac,
    rsa::{OaepPrivateDecryptingKey, PrivateDecryptingKey, OAEP_SHA1_MGF1SHA1},
    signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256},
};
use std::{hint::black_box, path::Path, time::Instant};
use zeroize::Zeroizing;

struct ValueKey {
    encryptor: PaddedBlockEncryptingKey,
    decryptor: PaddedBlockDecryptingKey,
    mac: hmac::Key,
    iv: hmac::Key,
}

impl ValueKey {
    fn new(working: &[u8]) -> Self {
        Self {
            encryptor: PaddedBlockEncryptingKey::cbc_pkcs7(
                UnboundCipherKey::new(&AES_256, &working[..32]).unwrap(),
            )
            .unwrap(),
            decryptor: PaddedBlockDecryptingKey::cbc_pkcs7(
                UnboundCipherKey::new(&AES_256, &working[..32]).unwrap(),
            )
            .unwrap(),
            mac: hmac::Key::new(hmac::HMAC_SHA256, &working[32..64]),
            iv: hmac::Key::new(hmac::HMAC_SHA256, &working[64..96]),
        }
    }

    fn encrypt(&self, plaintext: &[u8], randomized: bool) -> Vec<u8> {
        let mut iv = Zeroizing::new(vec![0_u8; 32]);
        if randomized {
            aws_lc_rs::rand::fill(&mut iv[..16]).unwrap();
        } else {
            hmac::sign_to_buffer(&self.iv, plaintext, &mut iv).unwrap();
        }
        let mut payload = Zeroizing::new(Vec::with_capacity(plaintext.len() + 16));
        payload.extend_from_slice(plaintext);
        self.encryptor
            .less_safe_encrypt(
                &mut *payload,
                EncryptionContext::Iv128(iv[..16].try_into().unwrap()),
            )
            .unwrap();
        let mut authenticated = Vec::with_capacity(payload.len() + 18);
        authenticated.push(1);
        authenticated.extend_from_slice(&iv[..16]);
        authenticated.extend_from_slice(&payload);
        authenticated.push(1);
        let mut output = vec![0_u8; 33];
        output[0] = 1;
        hmac::sign_to_buffer(&self.mac, &authenticated, &mut output[1..33]).unwrap();
        output.extend_from_slice(&authenticated[1..authenticated.len() - 1]);
        output
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, aws_lc_rs::error::Unspecified> {
        assert!(ciphertext.len() >= 65 && ciphertext[0] == 1);
        let mut authenticated = Vec::with_capacity(ciphertext.len() - 31);
        authenticated.push(1);
        authenticated.extend_from_slice(&ciphertext[33..]);
        authenticated.push(1);
        hmac::verify(&self.mac, &authenticated, &ciphertext[1..33])?;
        let mut payload = Zeroizing::new(ciphertext[49..].to_vec());
        let plaintext_len = self
            .decryptor
            .decrypt(
                &mut payload,
                DecryptionContext::Iv128(ciphertext[33..49].try_into().unwrap()),
            )?
            .len();
        payload.truncate(plaintext_len);
        Ok(payload)
    }
}

fn load(der: &[u8]) -> OaepPrivateDecryptingKey {
    OaepPrivateDecryptingKey::new(PrivateDecryptingKey::from_pkcs8(der).unwrap()).unwrap()
}

fn derive(
    master: &OaepPrivateDecryptingKey,
    public: &[u8],
    wrapped: &[u8],
    labels: &[Vec<u8>],
) -> Zeroizing<Vec<u8>> {
    let path_size = u16::from_le_bytes([wrapped[1], wrapped[2]]) as usize;
    let cipher_size = u16::from_le_bytes([wrapped[3], wrapped[4]]) as usize;
    let start = 5 + path_size;
    let end = start + cipher_size;
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public)
        .verify(&wrapped[..end], &wrapped[end..])
        .unwrap();
    let mut root_buffer = Zeroizing::new(vec![0_u8; master.min_output_size()]);
    let root = master
        .decrypt(
            &OAEP_SHA1_MGF1SHA1,
            &wrapped[start..end],
            &mut root_buffer,
            None,
        )
        .unwrap();
    assert_eq!(root.len(), 32);
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, root);
    let mut working = Zeroizing::new(vec![0_u8; 96]);
    for (index, label) in labels.iter().enumerate() {
        hmac::sign_to_buffer(&hmac_key, label, &mut working[index * 32..(index + 1) * 32]).unwrap();
    }
    working
}

fn measure(name: &str, mut operation: impl FnMut()) -> String {
    operation();
    let calibrate = Instant::now();
    operation();
    let count = (40_000_000 / calibrate.elapsed().as_nanos().max(1)).clamp(3, 100_000);
    let mut batches = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        for _ in 0..count {
            operation();
        }
        batches.push(start.elapsed().as_nanos() as f64 / count as f64 / 1000.0);
    }
    batches.sort_by(f64::total_cmp);
    format!("{{\"operation\":\"{name}\",\"median_wall_us\":{:.3},\"batch_mean_wall_range_us\":[{:.3},{:.3}],\"operations_per_batch\":{count},\"batches\":5}}", batches[2], batches[0], batches[4])
}

fn main() {
    let directory = std::env::args()
        .nth(1)
        .expect("synthetic fixture directory");
    let directory = Path::new(&directory);
    let der = Zeroizing::new(std::fs::read(directory.join("master.der")).unwrap());
    let expected = Zeroizing::new(std::fs::read(directory.join("working.bin")).unwrap());
    let public = std::fs::read(directory.join("public.der")).unwrap();
    let wrapped = std::fs::read(directory.join("wrapped.bin")).unwrap();
    let labels: Vec<Vec<u8>> = ["encryption key", "MAC key", "IV key"].iter().map(|kind| {
        format!("Microsoft SQL Server cell {kind} with encryption algorithm:AEAD_AES_256_CBC_HMAC_SHA256 and key length:256")
            .encode_utf16().flat_map(u16::to_le_bytes).collect()
    }).collect();
    let master = load(&der);
    assert_eq!(&*derive(&master, &public, &wrapped, &labels), &*expected);
    let mut results = vec![
        measure("parse_validate_drop_rsa_2048_from_der", || {
            drop(black_box(load(&der)));
        }),
        measure("verify_unwrap_derive_erase_with_parsed_master", || {
            drop(black_box(derive(&master, &public, &wrapped, &labels)));
        }),
        measure(
            "warm_der_file_load_parse_verify_unwrap_derive_erase",
            || {
                let input = Zeroizing::new(std::fs::read(directory.join("master.der")).unwrap());
                let key = load(&input);
                drop(black_box(derive(&key, &public, &wrapped, &labels)));
            },
        ),
        measure("twenty_exchanges_strict_key_work", || {
            for _ in 0..20 {
                let input = Zeroizing::new(std::fs::read(directory.join("master.der")).unwrap());
                let key = load(&input);
                drop(black_box(derive(&key, &public, &wrapped, &labels)));
            }
        }),
        measure(
            "twenty_exchanges_master_transaction_column_exchange_key_work",
            || {
                let input = Zeroizing::new(std::fs::read(directory.join("master.der")).unwrap());
                let key = load(&input);
                for _ in 0..20 {
                    drop(black_box(derive(&key, &public, &wrapped, &labels)));
                }
            },
        ),
        measure("twenty_exchanges_both_transaction_key_work", || {
            let input = Zeroizing::new(std::fs::read(directory.join("master.der")).unwrap());
            let key = load(&input);
            let working = derive(&key, &public, &wrapped, &labels);
            for _ in 0..20 {
                black_box(working.as_slice());
            }
        }),
    ];
    let root = Zeroizing::new(std::fs::read(directory.join("root.bin")).unwrap());
    results.push(measure("derive_three_working_keys_only", || {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &root);
        let mut output = Zeroizing::new(vec![0_u8; 96]);
        for (index, label) in labels.iter().enumerate() {
            hmac::sign_to_buffer(&key, label, &mut output[index * 32..(index + 1) * 32]).unwrap();
        }
        black_box(&*output);
    }));
    results.push(measure("prepare_aes_hmac_value_handles", || {
        drop(black_box(ValueKey::new(&expected)));
    }));
    let value_key = ValueKey::new(&expected);
    for size in [64, 1024, 65536] {
        let plaintext =
            Zeroizing::new(std::fs::read(directory.join(format!("plain-{size}.bin"))).unwrap());
        let deterministic = std::fs::read(directory.join(format!("det-{size}.bin"))).unwrap();
        let randomized = std::fs::read(directory.join(format!("random-{size}.bin"))).unwrap();
        assert!(value_key.encrypt(&plaintext, false) == deterministic);
        assert!(*value_key.decrypt(&deterministic).unwrap() == *plaintext);
        assert!(*value_key.decrypt(&randomized).unwrap() == *plaintext);
        let mut tampered = deterministic.clone();
        tampered[1] ^= 1;
        assert!(value_key.decrypt(&tampered).is_err());
        results.push(measure(
            &format!("encrypt_authenticate_deterministic_{size}_bytes"),
            || {
                drop(black_box(value_key.encrypt(&plaintext, false)));
            },
        ));
        results.push(measure(
            &format!("encrypt_authenticate_randomized_{size}_bytes"),
            || {
                drop(black_box(value_key.encrypt(&plaintext, true)));
            },
        ));
        results.push(measure(
            &format!("authenticate_decrypt_{size}_bytes"),
            || {
                drop(black_box(value_key.decrypt(&deterministic).unwrap()));
            },
        ));
    }
    println!("{{\"scope\":\"Candidate Rust aws-lc-rs 1.18.2, optimized, RSA-2048, wall time only; DER not PEM; no SQL or driver orchestration; value handles prepared once per key\",\"working_keys_match_python\":true,\"deterministic_ciphertext_and_decryption_match_python\":true,\"tampered_tags_rejected\":true,\"results\":[{}]}}", results.join(","));
}
