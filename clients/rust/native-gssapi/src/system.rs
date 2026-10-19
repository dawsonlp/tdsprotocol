//! RFC 2744 ABI. Names, credentials and contexts are exclusively owned; native
//! output buffers are released on success, continuation and every failure path.
use super::{Error, Evidence, MAX_TOKEN, Mechanism, Method, Step};
use std::{ffi::c_void, ptr};
use zeroize::Zeroizing;

type Handle = *mut c_void;
#[repr(C)]
struct Buffer {
    length: usize,
    value: *mut c_void,
}
impl Buffer {
    fn empty() -> Self {
        Self {
            length: 0,
            value: ptr::null_mut(),
        }
    }
    fn borrowed(bytes: &[u8]) -> Self {
        Self {
            length: bytes.len(),
            value: bytes.as_ptr().cast_mut().cast(),
        }
    }
}
#[repr(C)]
struct Oid {
    length: u32,
    elements: *mut c_void,
}
impl Oid {
    fn borrowed(bytes: &[u8]) -> Self {
        Self {
            length: bytes.len() as u32,
            elements: bytes.as_ptr().cast_mut().cast(),
        }
    }
}
#[repr(C)]
struct OidSet {
    count: usize,
    elements: *mut Oid,
}
#[repr(C)]
struct Bindings {
    initiator_addrtype: u32,
    initiator_address: Buffer,
    acceptor_addrtype: u32,
    acceptor_address: Buffer,
    application_data: Buffer,
}
const KERBEROS: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
const PRINCIPAL: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01";
const SPNEGO: &[u8] = b"\x2b\x06\x01\x05\x05\x02";
const NTLM: &[u8] = b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a";
const MUTUAL: u32 = 2;
const CONFIDENTIALITY: u32 = 16;
const INTEGRITY: u32 = 32;

// Only standard GSSAPI operations. macOS ships Heimdal in the GSS framework;
// Linux links MIT-compatible libgssapi_krb5 (development linker files required).
#[cfg_attr(target_os = "macos", link(name = "GSS", kind = "framework"))]
#[cfg_attr(target_os = "linux", link(name = "gssapi_krb5"))]
unsafe extern "C" {
    fn gss_import_name(
        minor: *mut u32,
        input: *const Buffer,
        kind: *const Oid,
        name: *mut Handle,
    ) -> u32;
    fn gss_release_name(minor: *mut u32, name: *mut Handle) -> u32;
    fn gss_acquire_cred(
        minor: *mut u32,
        name: Handle,
        time: u32,
        mechs: *const OidSet,
        usage: i32,
        credential: *mut Handle,
        actual: *mut *mut OidSet,
        lifetime: *mut u32,
    ) -> u32;
    fn gss_release_cred(minor: *mut u32, credential: *mut Handle) -> u32;
    #[cfg(target_os = "linux")]
    fn gss_set_neg_mechs(minor: *mut u32, credential: Handle, mechs: *const OidSet) -> u32;
    fn gss_init_sec_context(
        minor: *mut u32,
        credential: Handle,
        context: *mut Handle,
        target: Handle,
        mech: *const Oid,
        flags: u32,
        lifetime: u32,
        bindings: *const Bindings,
        input: *const Buffer,
        actual: *mut *mut Oid,
        output: *mut Buffer,
        returned_flags: *mut u32,
        returned_time: *mut u32,
    ) -> u32;
    fn gss_inquire_context(
        minor: *mut u32,
        context: Handle,
        source: *mut Handle,
        target: *mut Handle,
        lifetime: *mut u32,
        mechanism: *mut *mut Oid,
        flags: *mut u32,
        local: *mut i32,
        open: *mut i32,
    ) -> u32;
    fn gss_delete_sec_context(minor: *mut u32, context: *mut Handle, token: *mut Buffer) -> u32;
    fn gss_release_buffer(minor: *mut u32, buffer: *mut Buffer) -> u32;
}

/// A table keeps the ownership policy testable with controlled native outcomes.
/// The production table points only at the system GSSAPI implementation.
struct Calls {
    import: unsafe extern "C" fn(*mut u32, *const Buffer, *const Oid, *mut Handle) -> u32,
    release_name: unsafe extern "C" fn(*mut u32, *mut Handle) -> u32,
    acquire: unsafe extern "C" fn(
        *mut u32,
        Handle,
        u32,
        *const OidSet,
        i32,
        *mut Handle,
        *mut *mut OidSet,
        *mut u32,
    ) -> u32,
    release_cred: unsafe extern "C" fn(*mut u32, *mut Handle) -> u32,
    restrict: unsafe extern "C" fn(*mut u32, Handle, *const OidSet) -> u32,
    init: unsafe extern "C" fn(
        *mut u32,
        Handle,
        *mut Handle,
        Handle,
        *const Oid,
        u32,
        u32,
        *const Bindings,
        *const Buffer,
        *mut *mut Oid,
        *mut Buffer,
        *mut u32,
        *mut u32,
    ) -> u32,
    inquire: unsafe extern "C" fn(
        *mut u32,
        Handle,
        *mut Handle,
        *mut Handle,
        *mut u32,
        *mut *mut Oid,
        *mut u32,
        *mut i32,
        *mut i32,
    ) -> u32,
    delete: unsafe extern "C" fn(*mut u32, *mut Handle, *mut Buffer) -> u32,
    release_buffer: unsafe extern "C" fn(*mut u32, *mut Buffer) -> u32,
}
static SYSTEM: Calls = Calls {
    import: gss_import_name,
    release_name: gss_release_name,
    acquire: gss_acquire_cred,
    release_cred: gss_release_cred,
    #[cfg(target_os = "linux")]
    restrict: gss_set_neg_mechs,
    #[cfg(target_os = "macos")]
    restrict: restricted_at_acquisition,
    init: gss_init_sec_context,
    inquire: gss_inquire_context,
    delete: gss_delete_sec_context,
    release_buffer: gss_release_buffer,
};

#[cfg(target_os = "macos")]
unsafe extern "C" fn restricted_at_acquisition(_: *mut u32, _: Handle, _: *const OidSet) -> u32 {
    // Apple's Heimdal SPNEGO uses the mechglue credential directly, and its
    // offered mechanisms come from gss_inquire_cred on that credential. A
    // Kerberos-only acquisition is therefore the pre-token restriction. Apple
    // exports no gss_set_neg_mechs and cannot acquire a SPNEGO-only credential.
    0
}

struct Name {
    raw: Handle,
    calls: &'static Calls,
}
impl Name {
    fn new(value: &str, calls: &'static Calls) -> Result<Self, Error> {
        if value.is_empty() || value.len() > MAX_TOKEN || value.contains('\0') {
            return Err(Error::InvalidInput);
        }
        let mut result = Self {
            raw: ptr::null_mut(),
            calls,
        };
        let mut minor = 0;
        // GSS_KRB5_NT_PRINCIPAL_NAME preserves MSSQLSvc/host:port, unlike the
        // host-based service syntax (service@hostname). Inputs live through call.
        let status = unsafe {
            (calls.import)(
                &mut minor,
                &Buffer::borrowed(value.as_bytes()),
                &Oid::borrowed(PRINCIPAL),
                &mut result.raw,
            )
        };
        if status != 0 || result.raw.is_null() {
            return Err(Error::Refused);
        }
        Ok(result)
    }
}
impl Drop for Name {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe {
                (self.calls.release_name)(&mut 0, &mut self.raw);
            }
        }
    }
}
struct Output {
    buffer: Buffer,
    calls: &'static Calls,
}
impl Output {
    fn new(calls: &'static Calls) -> Self {
        Self {
            buffer: Buffer::empty(),
            calls,
        }
    }
    fn copy(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.buffer.length > MAX_TOKEN {
            return Err(Error::TokenLimit);
        }
        if self.buffer.length == 0 {
            return Ok(Zeroizing::new(Vec::new()));
        }
        if self.buffer.value.is_null() {
            return Err(Error::Refused);
        }
        // GSSAPI owns a buffer of the returned length until release_buffer.
        let bytes = unsafe {
            std::slice::from_raw_parts(self.buffer.value.cast::<u8>(), self.buffer.length)
        };
        Ok(Zeroizing::new(bytes.to_vec()))
    }
}
impl Drop for Output {
    fn drop(&mut self) {
        if !self.buffer.value.is_null() {
            // Native allocation erasure belongs to the library. Driver-owned
            // copies use Zeroizing; do not claim control over the system cache.
            unsafe {
                (self.calls.release_buffer)(&mut 0, &mut self.buffer);
            }
        }
    }
}

pub struct Context {
    credential: Handle,
    context: Handle,
    target: Name,
    method: Method,
    require_kerberos: bool,
    binding: Option<Vec<u8>>,
    terminal: bool,
    rounds: u8,
    calls: &'static Calls,
}
// GSSAPI handles are opaque, library-managed objects with no thread affinity.
// Ownership can move to a worker; &mut self prevents concurrent context calls.
unsafe impl Send for Context {}

impl Context {
    pub fn new(
        method: Method,
        target: &str,
        principal: Option<&str>,
        allow_ntlm: bool,
    ) -> Result<Self, Error> {
        Self::with_calls(method, target, principal, allow_ntlm, &SYSTEM)
    }
    fn with_calls(
        method: Method,
        target: &str,
        principal: Option<&str>,
        allow_ntlm: bool,
        calls: &'static Calls,
    ) -> Result<Self, Error> {
        let target = Name::new(target, calls)?;
        let desired = principal.map(|p| Name::new(p, calls)).transpose()?;
        let require_kerberos = method == Method::Kerberos || !allow_ntlm;
        let mut permitted = [Oid::borrowed(KERBEROS), Oid::borrowed(NTLM)];
        #[cfg(target_os = "linux")]
        let mut spnego = Oid::borrowed(SPNEGO);
        let mechs = OidSet {
            count: if require_kerberos { 1 } else { 2 },
            elements: permitted.as_mut_ptr(),
        };
        // Acquire the SPNEGO wrapper credential for Negotiate. On MIT GSSAPI,
        // a bare Kerberos credential has no set_neg_mechs operation: restriction
        // must apply to the wrapper before its first init_sec_context call.
        #[cfg(target_os = "linux")]
        let desired_mechs = OidSet {
            count: 1,
            elements: if method == Method::Negotiate {
                &mut spnego
            } else {
                &mut permitted[0]
            },
        };
        #[cfg(target_os = "linux")]
        let acquire_mechs: *const OidSet = &desired_mechs;
        #[cfg(target_os = "macos")]
        let acquire_mechs: *const OidSet = &mechs;
        let mut result = Self {
            credential: ptr::null_mut(),
            context: ptr::null_mut(),
            target,
            method,
            require_kerberos,
            binding: None,
            terminal: false,
            rounds: 0,
            calls,
        };
        let mut minor = 0;
        // A named principal selects that identity via GSSAPI; no parsing cache
        // files or guessing identity from a token. Default selection stays native.
        let status = unsafe {
            (calls.acquire)(
                &mut minor,
                desired.as_ref().map_or(ptr::null_mut(), |n| n.raw),
                u32::MAX,
                acquire_mechs,
                1,
                &mut result.credential,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if status != 0 || result.credential.is_null() {
            return Err(Error::Refused);
        }
        if method == Method::Negotiate {
            // Restrict BEFORE emitting a token; rejecting NTLM only after
            // completion could already have exposed an unwanted mechanism.
            let status = unsafe { (calls.restrict)(&mut minor, result.credential, &mechs) };
            if status != 0 {
                return Err(Error::Mechanism);
            }
        }
        Ok(result)
    }
    pub fn step(&mut self, challenge: Option<&[u8]>, binding: &[u8]) -> Result<Step, Error> {
        if self.terminal {
            return Err(Error::InvalidInput);
        }
        let result = self.step_inner(challenge, binding);
        if !matches!(&result, Ok(step) if !step.complete) {
            self.terminal = true;
        }
        result
    }
    fn step_inner(&mut self, challenge: Option<&[u8]>, binding: &[u8]) -> Result<Step, Error> {
        if self.rounds >= 8
            || (self.rounds == 0) != challenge.is_none()
            || challenge.is_some_and(|c| c.is_empty() || c.len() > MAX_TOKEN)
        {
            return Err(Error::InvalidInput);
        }
        let application = application_binding(binding)?;
        if self.binding.as_ref().is_some_and(|prior| prior != binding) {
            return Err(Error::InvalidInput);
        }
        self.binding.get_or_insert_with(|| binding.to_vec());
        self.rounds += 1;
        let bindings = Bindings {
            initiator_addrtype: 255,
            initiator_address: Buffer::empty(),
            acceptor_addrtype: 255,
            acceptor_address: Buffer::empty(),
            application_data: Buffer::borrowed(application),
        };
        let input = Buffer::borrowed(challenge.unwrap_or_default());
        let mech = Oid::borrowed(match self.method {
            Method::Kerberos => KERBEROS,
            Method::Negotiate => SPNEGO,
        });
        let mut output = Output::new(self.calls);
        let mut flags = 0;
        let mut minor = 0;
        let requested =
            CONFIDENTIALITY | INTEGRITY | if self.require_kerberos { MUTUAL } else { 0 };
        let status = unsafe {
            (self.calls.init)(
                &mut minor,
                self.credential,
                &mut self.context,
                self.target.raw,
                &mech,
                requested,
                0,
                if binding.is_empty() {
                    ptr::null()
                } else {
                    &bindings
                },
                if challenge.is_none() {
                    ptr::null()
                } else {
                    &input
                },
                ptr::null_mut(),
                &mut output.buffer,
                &mut flags,
                ptr::null_mut(),
            )
        };
        // Accept exactly COMPLETE or CONTINUE_NEEDED. Other supplementary
        // statuses (duplicate/old/out-of-sequence tokens) are not success.
        if status > 1 || self.context.is_null() {
            return Err(Error::Refused);
        }
        let complete = status == 0;
        let evidence = if complete {
            let mut actual = ptr::null_mut();
            let mut local = 0;
            let mut open = 0;
            let status = unsafe {
                (self.calls.inquire)(
                    &mut minor,
                    self.context,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut actual,
                    &mut flags,
                    &mut local,
                    &mut open,
                )
            };
            if status != 0 || local != 1 || open != 1 {
                return Err(Error::Refused);
            }
            // The returned OID is borrowed from the live context, never freed.
            let mechanism = unsafe { mechanism(actual) }?;
            if mechanism == Mechanism::Other {
                return Err(Error::Mechanism);
            }
            if self.require_kerberos && (mechanism != Mechanism::Kerberos || flags & MUTUAL == 0) {
                return Err(Error::Mechanism);
            }
            Some(Evidence {
                mechanism,
                channel_binding_supplied: !binding.is_empty(),
            })
        } else {
            None
        };
        Ok(Step {
            token: output.copy()?,
            complete,
            evidence,
        })
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        if !self.context.is_null() {
            let mut output = Output::new(self.calls);
            unsafe {
                (self.calls.delete)(&mut 0, &mut self.context, &mut output.buffer);
            }
        }
        if !self.credential.is_null() {
            unsafe {
                (self.calls.release_cred)(&mut 0, &mut self.credential);
            }
        }
        // target Name releases last, after context and credential teardown.
    }
}

unsafe fn mechanism(oid: *const Oid) -> Result<Mechanism, Error> {
    if oid.is_null() {
        return Err(Error::Mechanism);
    }
    let oid = unsafe { &*oid };
    if oid.elements.is_null() || oid.length == 0 || oid.length > 128 {
        return Err(Error::Mechanism);
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(oid.elements.cast::<u8>(), oid.length as usize) };
    Ok(if bytes == KERBEROS {
        Mechanism::Kerberos
    } else if bytes == NTLM {
        Mechanism::Ntlm
    } else {
        Mechanism::Other
    })
}

/// Convert the existing SSPI SEC_CHANNEL_BINDINGS layout to GSSAPI application
/// data. Do not send the 32-byte SSPI header as part of the binding itself.
fn application_binding(binding: &[u8]) -> Result<&[u8], Error> {
    if binding.is_empty() {
        return Ok(&[]);
    }
    if binding.len() < 32 || binding.len() > MAX_TOKEN || binding[..24] != [0; 24] {
        return Err(Error::InvalidInput);
    }
    let length = u32::from_le_bytes(binding[24..28].try_into().unwrap()) as usize;
    let offset = u32::from_le_bytes(binding[28..32].try_into().unwrap()) as usize;
    if offset != 32 || length == 0 || length != binding.len() - 32 {
        return Err(Error::InvalidInput);
    }
    Ok(&binding[32..])
}

#[cfg(test)]
mod tests;
