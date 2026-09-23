//! vuc-platform-uefi — ABI C du runtime Slura pour cible x86_64-unknown-uefi.
//! Pas d'allocateur propre — utilise celui de lunee-ker via le link final.

#![no_std]
#![allow(static_mut_refs)]

use core::ffi::c_char;

// Le panic handler est fourni par lunee-ker via uefi_services.
// Ce crate est compilé comme dépendance de lunee-ker — pas de panic handler ici.

// ── Exécuteur OVC — enregistré par lunee-ker au boot ─────────────────────────

type OvcExecutorFn = unsafe extern "C" fn(*const u8, usize, *const u8) -> i32;
static mut OVC_EXECUTOR: Option<OvcExecutorFn> = None;

#[no_mangle]
pub unsafe extern "C" fn slura_mgc_register_executor(f: OvcExecutorFn) {
    OVC_EXECUTOR = Some(f);
}

#[no_mangle]
pub unsafe extern "C" fn slura_mgc_execute(
    bytecode: *const u8, bytecode_len: usize,
    entry:    *const c_char, _gas: u64, _caller: *const c_char,
) -> i32 {
    if bytecode.is_null() || bytecode_len == 0 { return -1; }
    match OVC_EXECUTOR {
        Some(f) => f(
            bytecode, bytecode_len,
            if entry.is_null() { b"OEntry\0".as_ptr() } else { entry as _ },
        ),
        None => -3,
    }
}

#[no_mangle]
pub unsafe extern "C" fn slura_mgc_version(buf: *mut c_char, buf_len: usize) -> usize {
    const VER: &[u8] = b"vuc_platform_uefi 0.1.0 (UEFI no_std)\0";
    let n = VER.len().min(buf_len);
    if !buf.is_null() { core::ptr::copy_nonoverlapping(VER.as_ptr(), buf as _, n); }
    n.saturating_sub(1)
}

// ── RPC sur EFI TCP4 (polling synchrone, pas de tokio) ────────────────────────

static mut RPC_PORT: u16     = 0;
static mut RPC_EP:   [u8;64] = [0u8; 64];

#[no_mangle]
pub unsafe extern "C" fn slura_engine_rpc_start(endpoint: *const c_char) -> i32 {
    if endpoint.is_null() { return -1; }
    let s = cstr_bytes(endpoint as _);
    RPC_PORT = parse_port(s).unwrap_or(8080);
    let n = s.len().min(RPC_EP.len() - 1);
    core::ptr::copy_nonoverlapping(s.as_ptr(), RPC_EP.as_mut_ptr(), n);
    RPC_EP[n] = 0;
    0  // EFI_TCP4_PROTOCOL initialisé par lunee-ker — poll via rpc_poll()
}

#[no_mangle]
pub unsafe extern "C" fn slura_engine_rpc_endpoint(buf: *mut c_char, buf_len: usize) -> usize {
    if buf.is_null() || buf_len == 0 { return 0; }
    let mut n = 0usize;
    while n < buf_len - 1 && RPC_EP[n] != 0 { n += 1; }
    core::ptr::copy_nonoverlapping(RPC_EP.as_ptr(), buf as _, n);
    *(buf as *mut u8).add(n) = 0;
    n
}

/// Buffer de réponse statique (pas d'allocateur requis).
static mut RESP_BUF: [u8; 256] = [0u8; 256];

#[no_mangle]
pub unsafe extern "C" fn slura_engine_rpc_call(
    method: *const c_char, _params: *const c_char,
    result: *mut c_char, result_len: usize,
) -> i32 {
    if result.is_null() || result_len == 0 { return -1; }
    let resp = dispatch_rpc(method);
    let n = resp.len().min(result_len - 1);
    core::ptr::copy_nonoverlapping(resp.as_ptr(), result as _, n);
    *(result as *mut u8).add(n) = 0;
    0
}

fn dispatch_rpc(method: *const c_char) -> &'static [u8] {
    if method.is_null() { return b"{\"error\":\"null method\"}\0"; }
    let m = unsafe { cstr_bytes(method as _) };
    match m {
        b"slura_version"     => b"{\"result\":\"Slura OS 0.1.0\"}\0",
        b"slura_blockNumber" => b"{\"result\":\"0x1\"}\0",
        b"eth_chainId"       => b"{\"result\":\"0x534c5241\"}\0",
        b"net_version"       => b"{\"result\":\"1395920193\"}\0",
        b"eth_getBalance"    => b"{\"result\":\"0x0\"}\0",
        b"eth_gasPrice"      => b"{\"result\":\"0x1\"}\0",
        _                    => b"{\"error\":\"method not found\"}\0",
    }
}

unsafe fn cstr_bytes(p: *const u8) -> &'static [u8] {
    let mut n = 0usize;
    while *p.add(n) != 0 { n += 1; }
    core::slice::from_raw_parts(p, n)
}

fn parse_port(s: &[u8]) -> Option<u16> {
    let colon = s.iter().rposition(|&b| b == b':')?;
    let mut n: u16 = 0;
    for &b in &s[colon + 1..] {
        if b < b'0' || b > b'9' { break; }
        n = n.wrapping_mul(10).wrapping_add((b - b'0') as u16);
    }
    if n == 0 { None } else { Some(n) }
}
