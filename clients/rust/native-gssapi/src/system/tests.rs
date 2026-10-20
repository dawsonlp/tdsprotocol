//! Controlled native-call outcomes exercise the actual owner/wrapper paths.
//! Thread-local fake state isolates parallel tests; no OS credentials are read.
use super::*;
use std::{cell::RefCell, collections::VecDeque};

struct Fixture {
    names: usize,
    credentials: usize,
    contexts: usize,
    buffers: usize,
    imported: Vec<String>,
    acquired_principal: Option<String>,
    acquired_spnego: bool,
    restricted: bool,
    statuses: VecDeque<u32>,
    acquire_status: u32,
    acquire_minor: u32,
    restrict_status: u32,
    inquire_status: u32,
    actual: &'static [u8],
    mutual: bool,
    output_length: usize,
    binding: Vec<u8>,
}
impl Default for Fixture {
    fn default() -> Self {
        Self {
            names: 0,
            credentials: 0,
            contexts: 0,
            buffers: 0,
            imported: Vec::new(),
            acquired_principal: None,
            acquired_spnego: false,
            restricted: false,
            statuses: [1, 0].into(),
            acquire_status: 0,
            acquire_minor: 0,
            restrict_status: 0,
            inquire_status: 0,
            actual: KERBEROS,
            mutual: true,
            output_length: 16,
            binding: Vec::new(),
        }
    }
}
thread_local! { static FIXTURE: RefCell<Fixture> = RefCell::new(Fixture::default()); }
fn reset(change: impl FnOnce(&mut Fixture)) {
    FIXTURE.with_borrow_mut(|f| {
        *f = Fixture::default();
        change(f);
    });
}
fn clean() {
    FIXTURE.with_borrow(|f| {
        assert_eq!(
            (f.names, f.credentials, f.contexts, f.buffers),
            (0, 0, 0, 0)
        )
    });
}
unsafe fn bytes(buffer: *const Buffer) -> &'static [u8] {
    unsafe { std::slice::from_raw_parts((*buffer).value.cast::<u8>(), (*buffer).length) }
}
unsafe fn output(buffer: *mut Buffer, length: usize) {
    let value = vec![42_u8; length].into_boxed_slice();
    unsafe {
        *buffer = Buffer {
            length,
            value: Box::into_raw(value).cast(),
        };
    }
    FIXTURE.with_borrow_mut(|f| f.buffers += 1);
}
unsafe extern "C" fn import(
    _: *mut u32,
    value: *const Buffer,
    kind: *const Oid,
    name: *mut Handle,
) -> u32 {
    unsafe {
        assert_eq!(
            std::slice::from_raw_parts((*kind).elements.cast::<u8>(), (*kind).length as usize),
            PRINCIPAL
        );
        let text = String::from_utf8(bytes(value).to_vec()).unwrap();
        FIXTURE.with_borrow_mut(|f| {
            f.names += 1;
            f.imported.push(text.clone());
        });
        *name = Box::into_raw(Box::new(text)).cast();
    }
    0
}
unsafe extern "C" fn release_name(_: *mut u32, name: *mut Handle) -> u32 {
    unsafe {
        drop(Box::from_raw((*name).cast::<String>()));
        *name = ptr::null_mut();
    }
    FIXTURE.with_borrow_mut(|f| f.names -= 1);
    0
}
unsafe extern "C" fn acquire(
    minor: *mut u32,
    name: Handle,
    _: u32,
    mechs: *const OidSet,
    usage: i32,
    credential: *mut Handle,
    _: *mut *mut OidSet,
    _: *mut u32,
) -> u32 {
    assert_eq!(usage, 1);
    unsafe {
        *credential = Box::into_raw(Box::new(42_u8)).cast();
        FIXTURE.with_borrow_mut(|f| {
            f.credentials += 1;
            f.acquired_principal = (!name.is_null()).then(|| (&*name.cast::<String>()).clone());
            if !mechs.is_null() {
                let oid = &*(*mechs).elements;
                let bytes =
                    std::slice::from_raw_parts(oid.elements.cast::<u8>(), oid.length as usize);
                assert!(bytes == KERBEROS || bytes == SPNEGO);
                f.acquired_spnego = bytes == SPNEGO;
            }
            *minor = f.acquire_minor;
            f.acquire_status
        })
    }
}
unsafe extern "C" fn release_cred(_: *mut u32, cred: *mut Handle) -> u32 {
    unsafe {
        drop(Box::from_raw((*cred).cast::<u8>()));
        *cred = ptr::null_mut();
    }
    FIXTURE.with_borrow_mut(|f| f.credentials -= 1);
    0
}
unsafe extern "C" fn restrict(_: *mut u32, _: Handle, mechs: *const OidSet) -> u32 {
    unsafe {
        assert!((1..=2).contains(&(*mechs).count));
        let oid = &*(*mechs).elements;
        assert_eq!(
            std::slice::from_raw_parts(oid.elements.cast::<u8>(), oid.length as usize),
            KERBEROS
        );
    }
    FIXTURE.with_borrow_mut(|f| {
        f.restricted = true;
        f.restrict_status
    })
}
unsafe extern "C" fn init(
    _: *mut u32,
    _: Handle,
    context: *mut Handle,
    _: Handle,
    _: *const Oid,
    _: u32,
    _: u32,
    binding: *const Bindings,
    _: *const Buffer,
    _: *mut *mut Oid,
    out: *mut Buffer,
    _: *mut u32,
    _: *mut u32,
) -> u32 {
    unsafe {
        if (*context).is_null() {
            let actual = FIXTURE.with_borrow(|f| f.actual);
            *context = Box::into_raw(Box::new(Oid::borrowed(actual))).cast();
            FIXTURE.with_borrow_mut(|f| f.contexts += 1);
        }
        if !binding.is_null() {
            assert_eq!((*binding).initiator_addrtype, 255);
            assert_eq!((*binding).acceptor_addrtype, 255);
            FIXTURE.with_borrow_mut(|f| f.binding = bytes(&(*binding).application_data).to_vec());
        }
        output(out, FIXTURE.with_borrow(|f| f.output_length));
    }
    FIXTURE.with_borrow_mut(|f| f.statuses.pop_front().unwrap_or(0))
}
unsafe extern "C" fn inquire(
    _: *mut u32,
    context: Handle,
    _: *mut Handle,
    _: *mut Handle,
    _: *mut u32,
    mech: *mut *mut Oid,
    flags: *mut u32,
    local: *mut i32,
    open: *mut i32,
) -> u32 {
    unsafe {
        *mech = context.cast();
        *local = 1;
        *open = 1;
        FIXTURE.with_borrow(|f| {
            *flags = INTEGRITY | CONFIDENTIALITY | if f.mutual { MUTUAL } else { 0 };
            f.inquire_status
        })
    }
}
unsafe extern "C" fn delete(_: *mut u32, context: *mut Handle, out: *mut Buffer) -> u32 {
    unsafe {
        drop(Box::from_raw((*context).cast::<Oid>()));
        *context = ptr::null_mut();
        output(out, 8);
    }
    FIXTURE.with_borrow_mut(|f| f.contexts -= 1);
    0
}
unsafe extern "C" fn release_buffer(_: *mut u32, buffer: *mut Buffer) -> u32 {
    unsafe {
        drop(Box::from_raw(ptr::slice_from_raw_parts_mut(
            (*buffer).value.cast::<u8>(),
            (*buffer).length,
        )));
        *buffer = Buffer::empty();
    }
    FIXTURE.with_borrow_mut(|f| f.buffers -= 1);
    0
}
static FAKE: Calls = Calls {
    import,
    release_name,
    acquire,
    release_cred,
    restrict,
    init,
    inquire,
    delete,
    release_buffer,
};
fn context(method: Method, principal: Option<&str>, allow_ntlm: bool) -> Result<Context, Error> {
    Context::with_calls(
        method,
        "MSSQLSvc/sql.test:1433",
        principal,
        allow_ntlm,
        &FAKE,
    )
}
fn binding() -> Vec<u8> {
    let mut binding = vec![0; 32];
    binding[24..28].copy_from_slice(&3_u32.to_le_bytes());
    binding[28..32].copy_from_slice(&32_u32.to_le_bytes());
    binding.extend(b"abc");
    binding
}

#[test]
fn named_cache_identity_service_target_binding_and_completed_mechanism_are_distinct() {
    reset(|_| {});
    let mut ctx = context(Method::Negotiate, Some("user@TDS.TEST"), false).unwrap();
    FIXTURE.with_borrow(|f| {
        assert_eq!(f.imported, ["MSSQLSvc/sql.test:1433", "user@TDS.TEST"]);
        assert_eq!(f.acquired_principal.as_deref(), Some("user@TDS.TEST"));
        assert!(f.restricted);
        assert_eq!(f.acquired_spnego, cfg!(target_os = "linux"));
    });
    let first = ctx.step(None, &binding()).unwrap();
    assert!(!first.complete);
    assert!(first.evidence.is_none());
    let last = ctx.step(Some(b"server-token"), &binding()).unwrap();
    assert_eq!(
        last.evidence,
        Some(Evidence {
            mechanism: Mechanism::Kerberos,
            channel_binding_supplied: true
        })
    );
    FIXTURE.with_borrow(|f| assert_eq!(f.binding, b"abc"));
    assert!(ctx.step(Some(b"extra"), &binding()).is_err());
    drop(ctx);
    clean();
}
#[test]
fn default_identity_stays_native_and_ntlm_requires_explicit_fallback() {
    reset(|f| {
        f.actual = NTLM;
        f.statuses = [0].into();
    });
    let mut ctx = context(Method::Negotiate, None, false).unwrap();
    FIXTURE.with_borrow(|f| {
        assert!(f.acquired_principal.is_none());
        assert!(f.restricted);
    });
    assert!(matches!(ctx.step(None, &[]), Err(Error::Mechanism)));
    drop(ctx);
    clean();
    reset(|f| {
        f.actual = NTLM;
        f.mutual = false;
        f.statuses = [0].into();
    });
    let mut ctx = context(Method::Negotiate, None, true).unwrap();
    assert_eq!(
        ctx.step(None, &[]).unwrap().evidence.unwrap().mechanism,
        Mechanism::Ntlm
    );
    FIXTURE.with_borrow(|f| assert!(f.restricted));
    drop(ctx);
    clean();
}
#[test]
fn acquisition_restriction_and_context_failures_release_even_partial_outputs() {
    reset(|f| f.acquire_status = 0xd0000);
    assert!(context(Method::Kerberos, None, false).is_err());
    clean();
    reset(|f| f.restrict_status = 0xd0000);
    assert!(context(Method::Negotiate, None, false).is_err());
    clean();
    for status in [2, 4, 8, 16, 0xd0000] {
        reset(|f| f.statuses = [status].into());
        let mut ctx = context(Method::Kerberos, None, false).unwrap();
        assert!(matches!(ctx.step(None, &[]), Err(Error::Refused(s)) if s.major == status));
        assert!(ctx.step(None, &[]).is_err());
        drop(ctx);
        clean();
    }
    reset(|f| {
        f.statuses = [0].into();
        f.inquire_status = 0xd0000;
    });
    let mut ctx = context(Method::Kerberos, None, false).unwrap();
    assert!(ctx.step(None, &[]).is_err());
    drop(ctx);
    clean();
}
#[test]
fn bounded_output_mutual_auth_rounds_and_unchanged_binding_are_enforced() {
    reset(|f| f.output_length = MAX_TOKEN + 1);
    let mut ctx = context(Method::Kerberos, None, false).unwrap();
    assert!(matches!(ctx.step(None, &[]), Err(Error::TokenLimit)));
    drop(ctx);
    clean();
    reset(|f| {
        f.mutual = false;
        f.statuses = [0].into();
    });
    let mut ctx = context(Method::Kerberos, None, false).unwrap();
    assert!(matches!(ctx.step(None, &[]), Err(Error::Mechanism)));
    drop(ctx);
    clean();
    reset(|f| f.statuses = [1; 9].into());
    let mut ctx = context(Method::Kerberos, None, false).unwrap();
    ctx.step(None, &[]).unwrap();
    for _ in 1..8 {
        ctx.step(Some(b"challenge"), &[]).unwrap();
    }
    assert!(ctx.step(Some(b"challenge"), &[]).is_err());
    drop(ctx);
    clean();
    reset(|_| {});
    let mut ctx = context(Method::Negotiate, None, false).unwrap();
    ctx.step(None, &binding()).unwrap();
    assert!(ctx.step(Some(b"challenge"), &[]).is_err());
    drop(ctx);
    clean();
}
#[test]
fn malformed_names_and_binding_headers_are_rejected_without_native_exchange() {
    for name in ["", "a\0b"] {
        assert!(Name::new(name, &FAKE).is_err());
    }
    assert!(application_binding(&[0; 31]).is_err());
    let mut bad = binding();
    bad[0] = 1;
    assert!(application_binding(&bad).is_err());
    let mut bad = binding();
    bad[28] = 31;
    assert!(application_binding(&bad).is_err());
    let mut bad = binding();
    bad.push(0);
    assert!(application_binding(&bad).is_err());
    reset(|_| {});
    let mut ctx = context(Method::Kerberos, None, false).unwrap();
    assert!(ctx.step(Some(b"unsolicited"), &[]).is_err());
    drop(ctx);
    clean();
}

#[test]
fn system_library_imports_and_releases_principal_names_without_credentials() {
    // Exercises the actual platform ABI/linkage, without touching a cache/KDC.
    let target = Name::new("MSSQLSvc/sql.test:1433", &SYSTEM).unwrap();
    let principal = Name::new("fixture@TDS.TEST", &SYSTEM).unwrap();
    drop((target, principal));
}

#[test]
fn refusals_keep_status_numbers_that_tell_absent_from_expired_credentials() {
    use crate::{Status, StatusKind};
    // Statuses observed from MIT Kerberos on the campaign runner: no ticket
    // (GSS_S_NO_CRED) and an expired one (GSS_S_FAILURE, ticket-expired minor).
    // Other failures stay Failure; minors pass through unchanged.
    for (major, minor, kind) in [
        (0x70000, 0x96c7_3a8d, StatusKind::NoCredentials),
        (0xb0000, 0, StatusKind::CredentialsExpired),
        (0xd0000, 0x96c7_3a20, StatusKind::CredentialsExpired),
        (0xd0000, 0x96c7_3a27, StatusKind::Failure),
    ] {
        reset(|f| {
            f.acquire_status = major;
            f.acquire_minor = minor;
        });
        let Err(Error::Refused(status)) = context(Method::Kerberos, None, false) else {
            panic!("refused")
        };
        assert_eq!(status, Status { major, minor });
        assert_eq!(status.kind(), kind);
        clean();
    }
}
