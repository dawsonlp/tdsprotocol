//! Small audited FFI boundary. Certificate DER is public; private keys are never
//! exported. Every native handle has one owner, including failure paths.
#![deny(unsafe_op_in_unsafe_fn)]
use super::Error;
use std::{ffi::c_void, sync::Mutex};
use zeroize::{Zeroize, Zeroizing};
#[repr(C)]
struct HashBlob {
    len: u32,
    bytes: *const u8,
}
#[repr(C)]
struct CertContext {
    encoding: u32,
    der: *const u8,
    len: u32,
    info: *const c_void,
    store: usize,
}
#[repr(C)]
struct OaepPadding {
    algorithm: *const u16,
    label: *const u8,
    length: u32,
}
#[repr(C)]
struct Pkcs1Padding {
    algorithm: *const u16,
}
#[link(name = "crypt32")]
unsafe extern "system" {
    fn CertOpenStore(
        provider: usize,
        encoding: u32,
        crypt_provider: usize,
        flags: u32,
        parameter: *const c_void,
    ) -> usize;
    fn CertFindCertificateInStore(
        store: usize,
        encoding: u32,
        flags: u32,
        find: u32,
        parameter: *const c_void,
        previous: *const CertContext,
    ) -> *const CertContext;
    fn CertFreeCertificateContext(context: *const CertContext) -> i32;
    fn CertCloseStore(store: usize, flags: u32) -> i32;
    fn CryptAcquireCertificatePrivateKey(
        context: *const CertContext,
        flags: u32,
        reserved: *const c_void,
        key: *mut usize,
        spec: *mut u32,
        free: *mut i32,
    ) -> i32;
}
#[link(name = "ncrypt")]
unsafe extern "system" {
    fn NCryptDecrypt(
        key: usize,
        input: *const u8,
        input_len: u32,
        padding: *const c_void,
        output: *mut u8,
        output_len: u32,
        result: *mut u32,
        flags: u32,
    ) -> i32;
    fn NCryptSignHash(
        key: usize,
        padding: *const c_void,
        digest: *const u8,
        digest_len: u32,
        output: *mut u8,
        output_len: u32,
        result: *mut u32,
        flags: u32,
    ) -> i32;
    fn NCryptFreeObject(handle: usize) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLastError() -> u32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn CryptReleaseContext(handle: usize, flags: u32) -> i32;
}
struct Private {
    handle: usize,
    free: bool,
    cng: bool,
}
pub struct Certificate {
    store: usize,
    context: usize,
    private: Mutex<Option<Private>>,
    der: Vec<u8>,
}
impl Certificate {
    /// Location is CERT_SYSTEM_STORE_CURRENT_USER or LOCAL_MACHINE. The driver
    /// parses the external path; this boundary rejects embedded NULs as well.
    pub fn open(location: u32, store_name: &str, thumbprint: &[u8]) -> Result<Self, Error> {
        if ![0x10000, 0x20000].contains(&location)
            || store_name.contains('\0')
            || thumbprint.is_empty()
        {
            return Err(Error(87));
        }
        let name: Vec<u16> = store_name.encode_utf16().chain([0]).collect();
        // All pointers borrow owned input buffers for the duration of the call.
        let store =
            unsafe { CertOpenStore(10, 0, 0, location | 0x8000 | 0x4000, name.as_ptr().cast()) };
        if store == 0 {
            return Err(Error(unsafe { GetLastError() }));
        }
        let mut owned = Self {
            store,
            context: 0,
            private: Mutex::new(None),
            der: Vec::new(),
        };
        let hash = HashBlob {
            len: thumbprint.len().try_into().map_err(|_| Error(87))?,
            bytes: thumbprint.as_ptr(),
        };
        let context = unsafe {
            CertFindCertificateInStore(
                store,
                0x10001,
                0,
                0x10000,
                (&hash as *const HashBlob).cast(),
                std::ptr::null(),
            )
        };
        if context.is_null() {
            return Err(Error(unsafe { GetLastError() }));
        }
        owned.context = context as usize;
        // Context owns these DER bytes until CertFreeCertificateContext.
        let context = unsafe { &*context };
        if context.len == 0 || context.len > 1_048_576 || context.der.is_null() {
            return Err(Error(13));
        }
        owned.der =
            unsafe { std::slice::from_raw_parts(context.der, context.len as usize) }.to_vec();
        Ok(owned)
    }
    pub fn der(&self) -> &[u8] {
        &self.der
    }
    fn with_private<T>(&self, work: impl FnOnce(usize) -> Result<T, Error>) -> Result<T, Error> {
        let mut private = self
            .private
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if private.is_none() {
            let (mut key, mut spec, mut free) = (0, 0, 0);
            let acquired = unsafe {
                CryptAcquireCertificatePrivateKey(
                    self.context as *const CertContext,
                    0x40000 | 0x40,
                    std::ptr::null(),
                    &mut key,
                    &mut spec,
                    &mut free,
                )
            };
            if acquired == 0 {
                return Err(Error(unsafe { GetLastError() }));
            }
            // ONLY_NCRYPT guarantees a CNG handle. Preserve caller-free ownership
            // even on an unexpected key specification.
            *private = Some(Private {
                handle: key,
                free: free != 0,
                cng: spec == u32::MAX,
            });
        }
        if !private.as_ref().unwrap().cng {
            return Err(Error(13));
        }
        work(private.as_ref().unwrap().handle)
    }
    pub fn decrypt_oaep_sha1(&self, input: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        if input.is_empty() || input.len() > 1024 {
            return Err(Error(87));
        }
        self.with_private(|key| {
            let algorithm: Vec<u16> = "SHA1".encode_utf16().chain([0]).collect();
            let padding = OaepPadding {
                algorithm: algorithm.as_ptr(),
                label: std::ptr::null(),
                length: 0,
            };
            let mut output = Zeroizing::new(vec![0; input.len()]);
            let mut size = 0;
            let status = unsafe {
                NCryptDecrypt(
                    key,
                    input.as_ptr(),
                    input.len() as u32,
                    (&padding as *const OaepPadding).cast(),
                    output.as_mut_ptr(),
                    output.len() as u32,
                    &mut size,
                    4,
                )
            };
            if status != 0 {
                return Err(Error(status as u32));
            }
            if size as usize > output.len() {
                return Err(Error(13));
            }
            output[size as usize..].zeroize();
            output.truncate(size as usize);
            Ok(output)
        })
    }
    pub fn sign_sha256_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, Error> {
        self.with_private(|key| {
            let algorithm: Vec<u16> = "SHA256".encode_utf16().chain([0]).collect();
            let padding = Pkcs1Padding {
                algorithm: algorithm.as_ptr(),
            };
            let mut output = vec![0; 1024];
            let mut size = 0;
            let status = unsafe {
                NCryptSignHash(
                    key,
                    (&padding as *const Pkcs1Padding).cast(),
                    digest.as_ptr(),
                    32,
                    output.as_mut_ptr(),
                    output.len() as u32,
                    &mut size,
                    2,
                )
            };
            if status != 0 {
                return Err(Error(status as u32));
            }
            if size as usize > output.len() {
                return Err(Error(13));
            }
            output.truncate(size as usize);
            Ok(output)
        })
    }
}
impl Drop for Certificate {
    fn drop(&mut self) {
        let private = self
            .private
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        // Keys acquired without caller-free ownership are owned by the cert
        // context. CNG keys are shared only through this synchronized owner.
        if let Some(Private {
            handle,
            free: true,
            cng,
        }) = private
        {
            if cng {
                unsafe { NCryptFreeObject(handle) };
            } else {
                unsafe { CryptReleaseContext(handle, 0) };
            }
        }
        if self.context != 0 {
            unsafe { CertFreeCertificateContext(self.context as *const CertContext) };
        }
        if self.store != 0 {
            unsafe { CertCloseStore(self.store, 0) };
        }
    }
}
