//! AEAD_AES_256_CBC_HMAC_SHA256, matching Python encryption/cell.py.
use super::{Error, Plaintext, Result, secret::Secret};
use aws_lc_rs::{
    cipher::{
        AES_256, DecryptingKey, EncryptionContext, PaddedBlockEncryptingKey, UnboundCipherKey,
    },
    hmac,
};
use zeroize::Zeroizing;
pub(super) const MAX_VALUE: usize = 16 * 1024 * 1024;

pub(super) struct Cell {
    encryptor: PaddedBlockEncryptingKey,
    // Decrypt without library padding removal, then validate it ourselves.
    decryptor: DecryptingKey,
    mac: hmac::Key,
    iv: hmac::Key,
}
impl Cell {
    pub(super) fn derive(
        root: &[u8],
        #[cfg(test)] audit: &Option<super::secret::Audit>,
    ) -> Result<Box<Self>> {
        if root.len() != 32 {
            return Err(Error::InvalidMetadata);
        }
        let mut working = Secret::new(96);
        #[cfg(test)]
        {
            working = working.audited(audit, "derived");
        }
        let key = hmac::Key::new(hmac::HMAC_SHA256, root);
        for (index, kind) in ["encryption key", "MAC key", "IV key"].iter().enumerate() {
            let label: Vec<_> = format!("Microsoft SQL Server cell {kind} with encryption algorithm:AEAD_AES_256_CBC_HMAC_SHA256 and key length:256")
                .encode_utf16().flat_map(u16::to_le_bytes).collect();
            hmac::sign_to_buffer(
                &key,
                &label,
                &mut working.bytes[index * 32..(index + 1) * 32],
            )
            .map_err(|_| Error::InvalidMetadata)?;
        }
        let result = Box::new(Self {
            encryptor: PaddedBlockEncryptingKey::cbc_pkcs7(
                UnboundCipherKey::new(&AES_256, &working.bytes[..32])
                    .map_err(|_| Error::InvalidMetadata)?,
            )
            .map_err(|_| Error::InvalidMetadata)?,
            decryptor: DecryptingKey::cbc(
                UnboundCipherKey::new(&AES_256, &working.bytes[..32])
                    .map_err(|_| Error::InvalidMetadata)?,
            )
            .map_err(|_| Error::InvalidMetadata)?,
            mac: hmac::Key::new(hmac::HMAC_SHA256, &working.bytes[32..64]),
            iv: hmac::Key::new(hmac::HMAC_SHA256, &working.bytes[64..96]),
        });
        // Drop explicitly before returning native handles; root's owner also
        // drops its guarded RSA plaintext immediately after this returns.
        drop(working);
        Ok(result)
    }
    pub(super) fn encrypt(&self, plaintext: &[u8], randomized: bool) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_VALUE {
            return Err(Error::ValueTooLarge);
        }
        let mut iv = [0_u8; 32]; // The IV and its HMAC are public ciphertext data.
        if randomized {
            aws_lc_rs::rand::fill(&mut iv[..16]).map_err(|_| Error::Worker)?;
        } else {
            hmac::sign_to_buffer(&self.iv, plaintext, &mut iv).map_err(|_| Error::Worker)?;
        }
        // Reserve final padding space before inserting plaintext: no secret
        // reallocation. zeroize also clears the buffer on encryption failure.
        let mut payload = Zeroizing::new(Vec::with_capacity(plaintext.len() + 16));
        payload.extend_from_slice(plaintext);
        self.encryptor
            .less_safe_encrypt(
                &mut *payload,
                EncryptionContext::Iv128(iv[..16].try_into().unwrap()),
            )
            .map_err(|_| Error::Worker)?;
        let mut authenticated = Vec::with_capacity(payload.len() + 18);
        authenticated.push(1);
        authenticated.extend_from_slice(&iv[..16]);
        authenticated.extend_from_slice(&payload);
        authenticated.push(1);
        let mut out = vec![0; 33];
        out[0] = 1;
        hmac::sign_to_buffer(&self.mac, &authenticated, &mut out[1..])
            .map_err(|_| Error::Worker)?;
        out.extend_from_slice(&authenticated[1..authenticated.len() - 1]);
        Ok(out)
    }
    pub(super) fn decrypt(&self, ciphertext: &[u8]) -> Result<Plaintext> {
        if ciphertext.len() > MAX_VALUE + 65 {
            return Err(Error::ValueTooLarge);
        }
        if ciphertext.len() < 65
            || ciphertext[0] != 1
            || !(ciphertext.len() - 49).is_multiple_of(16)
        {
            return Err(Error::InvalidCiphertext);
        }
        let mut authenticated = Vec::with_capacity(ciphertext.len() - 31);
        authenticated.push(1);
        authenticated.extend_from_slice(&ciphertext[33..]);
        authenticated.push(1);
        hmac::verify(&self.mac, &authenticated, &ciphertext[1..33])
            .map_err(|_| Error::Authentication)?;
        let mut storage = Secret::copy(&ciphertext[49..]);
        self.decryptor
            .decrypt(
                &mut storage.bytes,
                aws_lc_rs::cipher::DecryptionContext::Iv128(ciphertext[33..49].try_into().unwrap()),
            )
            .map_err(|_| Error::InvalidCiphertext)?;
        let padding = usize::from(*storage.bytes.last().unwrap());
        // Authentication has already succeeded. Validate every padding byte
        // without exposing any plaintext on an invalid encryptor's output.
        if padding == 0
            || padding > 16
            || storage.bytes[storage.bytes.len() - padding..]
                .iter()
                .any(|b| usize::from(*b) != padding)
        {
            return Err(Error::InvalidCiphertext);
        }
        let length = storage.bytes.len() - padding;
        if length > MAX_VALUE {
            return Err(Error::ValueTooLarge);
        }
        Ok(Plaintext { storage, length })
    }
}
