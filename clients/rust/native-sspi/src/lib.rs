//! Isolated FFI boundary; the protocol crate retains forbid(unsafe_code).
//! All SSPI pointers borrow live owned buffers for the duration of one call.
#![cfg(windows)]
use windows::{
    Win32::{
        Foundation::*,
        Security::{Authentication::Identity::*, Credentials::SecHandle},
    },
    core::PCWSTR,
};
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct Error;

pub struct Context {
    credential: SecHandle,
    context: SecHandle,
    has_context: bool,
    target: Vec<u16>,
    require_kerberos: bool,
    negotiating: bool,
}
impl Context {
    pub fn new(package: &str, target: &str, require_kerberos: bool) -> Result<Self, Error> {
        if target.is_empty() || target.contains('\0') {
            return Err(Error);
        }
        let negotiating = package == "Negotiate";
        let package: Vec<u16> = package.encode_utf16().chain([0]).collect();
        let mut credential = SecHandle::default();
        // Null auth data means the calling thread/process's signed-in identity.
        unsafe {
            AcquireCredentialsHandleW(
                PCWSTR::null(),
                PCWSTR(package.as_ptr()),
                SECPKG_CRED_OUTBOUND,
                None,
                None,
                None,
                None,
                &mut credential,
                None,
            )
            .map_err(|_| Error)?;
        }
        Ok(Self {
            credential,
            context: SecHandle::default(),
            has_context: false,
            target: target.encode_utf16().chain([0]).collect(),
            require_kerberos,
            negotiating,
        })
    }
    pub fn step(
        &mut self,
        challenge: Option<&[u8]>,
        binding: &[u8],
    ) -> Result<(Zeroizing<Vec<u8>>, bool), Error> {
        let mut challenge = Zeroizing::new(challenge.unwrap_or_default().to_vec());
        let mut binding = binding.to_vec();
        let mut input = Vec::new();
        if !challenge.is_empty() {
            input.push(SecBuffer {
                cbBuffer: challenge.len().try_into().map_err(|_| Error)?,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: challenge.as_mut_ptr().cast(),
            });
        }
        if !binding.is_empty() {
            input.push(SecBuffer {
                cbBuffer: binding.len().try_into().map_err(|_| Error)?,
                BufferType: SECBUFFER_CHANNEL_BINDINGS,
                pvBuffer: binding.as_mut_ptr().cast(),
            });
        }
        let input_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: input.len() as u32,
            pBuffers: input.as_mut_ptr(),
        };
        let mut output = Zeroizing::new(vec![0; 48 * 1024]);
        let mut output_buffer = SecBuffer {
            cbBuffer: output.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: output.as_mut_ptr().cast(),
        };
        let mut output_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut output_buffer,
        };
        let mut attributes = 0;
        let mut flags = ISC_REQ_CONNECTION | ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY;
        if self.require_kerberos {
            flags |= ISC_REQ_MUTUAL_AUTH;
        }
        let status = unsafe {
            InitializeSecurityContextW(
                Some(&self.credential),
                self.has_context.then_some(&self.context),
                Some(self.target.as_ptr()),
                flags,
                0,
                SECURITY_NATIVE_DREP,
                (!input.is_empty()).then_some(&input_desc),
                0,
                Some(&mut self.context),
                Some(&mut output_desc),
                &mut attributes,
                None,
            )
        };
        self.has_context = self.context.dwLower != 0 || self.context.dwUpper != 0;
        let complete = match status {
            SEC_E_OK => true,
            SEC_I_CONTINUE_NEEDED => false,
            SEC_I_COMPLETE_NEEDED | SEC_I_COMPLETE_AND_CONTINUE => {
                unsafe {
                    CompleteAuthToken(&self.context, &output_desc).map_err(|_| Error)?;
                }
                status == SEC_I_COMPLETE_NEEDED
            }
            _ => return Err(Error),
        };
        let len = output_buffer.cbBuffer as usize;
        if len > output.len() {
            return Err(Error);
        }
        output.truncate(len);
        if complete && self.require_kerberos && self.negotiating && !self.is_kerberos()? {
            return Err(Error);
        }
        Ok((output, complete))
    }
    fn is_kerberos(&self) -> Result<bool, Error> {
        let mut info = SecPkgContext_NegotiationInfoW::default();
        unsafe {
            QueryContextAttributesW(
                &self.context,
                SECPKG_ATTR_NEGOTIATION_INFO,
                (&mut info as *mut SecPkgContext_NegotiationInfoW).cast(),
            )
            .map_err(|_| Error)?;
            if info.PackageInfo.is_null() {
                return Err(Error);
            }
            let result = PCWSTR((*info.PackageInfo).Name)
                .to_string()
                .map(|name| name.eq_ignore_ascii_case("Kerberos"))
                .map_err(|_| Error);
            let _ = FreeContextBuffer(info.PackageInfo.cast());
            result
        }
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            if self.has_context {
                let _ = DeleteSecurityContext(&self.context);
            }
            let _ = FreeCredentialsHandle(&self.credential);
        }
    }
}
