//! Owned CNG boundary. Windows calls are isolated from the safe driver.
#[derive(Debug)]
pub struct Error(pub u32);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "certificate operation failed ({:#010x})", self.0)
    }
}
impl std::error::Error for Error {}

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::Certificate;

#[cfg(not(windows))]
pub struct Certificate;
#[cfg(not(windows))]
impl Certificate {
    pub fn open(_: u32, _: &str, _: &[u8]) -> Result<Self, Error> {
        Err(Error(120))
    }
    pub fn der(&self) -> &[u8] {
        &[]
    }
    pub fn decrypt_oaep_sha1(&self, _: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
        Err(Error(120))
    }
    pub fn sign_sha256_digest(&self, _: &[u8; 32]) -> Result<Vec<u8>, Error> {
        Err(Error(120))
    }
}
