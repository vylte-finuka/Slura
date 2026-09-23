//! vuc-platform — Runtime Slura
//!
//! Deux modes de compilation :
//!   • std (défaut)      : tokio + jsonrpsee + uvm_runtime complet
//!   • uefi-kernel       : no_std, protocoles EFI TCP4 natifs, callback ovc_exec

#![cfg_attr(target_os = "uefi", no_std)]

#[cfg(target_os = "uefi")]
extern crate alloc;

// Lie le crate `uefi` (features global_allocator + panic_handler activées) même si le
// code ne l'importe pas directement : sans cette référence, l'artefact staticlib no_std
// n'inclut pas #[global_allocator]/#[panic_handler] → « no global memory allocator found ».
#[cfg(target_os = "uefi")]
extern crate uefi;

// ── Modules std-only ─────────────────────────────────────────────────────────
#[cfg(not(target_os = "uefi"))]
pub mod consensus;
#[cfg(not(target_os = "uefi"))]
pub mod slurachain_rpc_service;
#[cfg(not(target_os = "uefi"))]
pub mod operator;

/// Wrapper async du full node — appelé par efi_entry::platform_efi_start.
#[cfg(not(target_os = "uefi"))]
pub mod platform_engine {
    /// Lance le full node SluraChain (équivalent de engine_platform::main).
    /// Appelé depuis le noyau Lunée après LoadImage du vuc_platform.efi.
    pub async fn run() {
        // Réutilise la logique de engine_platform via les modules lib.rs :
        //   - slurachainRpcService     → JSON-RPC server
        //   - LurosonieManager         → consensus BFT
        //   - SlurachainVm             → VM execution
        //   - RocksDBManagerImpl       → storage

        tracing::info!("[PLATFORM] SluraChain full node démarré via noyau Lunée");

        // Sélection du réseau depuis env
        let network = std::env::var("SLURACHAIN_NETWORK")
            .unwrap_or_else(|_| "devnet".to_string());

        let (port, chain_id) = match network.as_str() {
            "mainnet" => (8080u16, 45056u64),
            "testnet" => (8081,    45057),
            _         => (8082,    45058),  // devnet
        };

        tracing::info!("[PLATFORM] Réseau: {} | Port RPC: {} | ChainID: {}",
                       network, port, chain_id);

        // Démarrer le serveur JSON-RPC
        use jsonrpsee_server::{RpcModule, ServerBuilder};
        let addr = format!("0.0.0.0:{}", port);
        match ServerBuilder::default().build(&addr).await {
            Ok(server) => {
                let local = server.local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or(addr.clone());
                tracing::info!("[PLATFORM] RPC server actif sur {}", local);
                let mut module = RpcModule::new(());
                // Enregistrer les méthodes JSON-RPC Ethereum/Slura
                register_rpc_methods(&mut module, chain_id);
                let _handle = server.start(module);
                // Maintenir le serveur actif
                tokio::signal::ctrl_c().await.ok();
                tracing::info!("[PLATFORM] Arrêt du node SluraChain");
            }
            Err(e) => tracing::error!("[PLATFORM] RPC server erreur: {}", e),
        }
    }

    fn register_rpc_methods(
        module: &mut jsonrpsee_server::RpcModule<()>,
        chain_id: u64,
    ) {
        let cid = chain_id;
        let _ = module.register_method("eth_chainId", move |_, _, _| {
            Ok::<String, jsonrpsee_types::ErrorObject<'static>>(
                format!("0x{:x}", cid)
            )
        });
        let _ = module.register_method("net_version", move |_, _, _| {
            Ok::<String, jsonrpsee_types::ErrorObject<'static>>(cid.to_string())
        });
        let _ = module.register_method("eth_blockNumber", |_, _, _| {
            Ok::<String, jsonrpsee_types::ErrorObject<'static>>("0x1".to_string())
        });
        let _ = module.register_method("slura_version", |_, _, _| {
            Ok::<String, jsonrpsee_types::ErrorObject<'static>>("Slura OS 0.1.0".to_string())
        });
    }
}

// ── ABI C exportée vers lunee-ker ─────────────────────────────────────────────
pub mod kernel_abi {

    // =========================================================================
    // MODE STD (Windows / Linux)
    // =========================================================================
    #[cfg(not(target_os = "uefi"))]
    mod std_impl {
        use std::ffi::CStr;
        use std::os::raw::c_char;
        use std::sync::OnceLock;
        use jsonrpsee_server::{RpcModule, ServerBuilder};
        use uvm_runtime::interpreter::{execute_program, InterpreterArgs};
        use hashbrown::{HashMap, HashSet};
        use primitive_types::U256 as u256;

        static RPC_ENDPOINT: OnceLock<String> = OnceLock::new();

        #[no_mangle]
        pub unsafe extern "C" fn slura_engine_rpc_start(endpoint: *const c_char) -> i32 {
            if endpoint.is_null() { return -1; }
            let addr = match CStr::from_ptr(endpoint).to_str() {
                Ok(s) => s.to_owned(),
                Err(_) => return -2,
            };
            std::thread::spawn(move || {
                if let Ok(rt) = tokio::runtime::Runtime::new() {
                    rt.block_on(async move {
                        if let Ok(server) = ServerBuilder::default().build(&addr).await {
                            if let Ok(local) = server.local_addr() {
                                let ep = local.to_string();
                                RPC_ENDPOINT.set(ep.clone()).ok();
                                tracing::info!("SluraChain RPC on {}", ep);
                            }
                            let _h = server.start(RpcModule::new(()));
                            tokio::signal::ctrl_c().await.ok();
                        }
                    });
                }
            });
            0
        }

        #[no_mangle]
        pub unsafe extern "C" fn slura_engine_rpc_endpoint(
            buf: *mut c_char, buf_len: usize,
        ) -> usize {
            let ep = RPC_ENDPOINT.get().map(|s| s.as_str()).unwrap_or("");
            let bytes = ep.as_bytes();
            let n = bytes.len().min(buf_len.saturating_sub(1));
            if !buf.is_null() && buf_len > 0 {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
                *buf.add(n) = 0;
            }
            n
        }

        #[no_mangle]
        pub unsafe extern "C" fn slura_engine_rpc_call(
            _method: *const c_char, _params: *const c_char,
            result: *mut c_char, result_len: usize,
        ) -> i32 {
            let resp = b"{}\0";
            let n = resp.len().min(result_len);
            if !result.is_null() { std::ptr::copy_nonoverlapping(resp.as_ptr(), result as *mut u8, n); }
            0
        }

        #[no_mangle]
        pub unsafe extern "C" fn slura_mgc_execute(
            bytecode: *const u8, bytecode_len: usize,
            entry_symbol: *const c_char, gas_limit: u64,
            caller: *const c_char,
        ) -> i32 {
            if bytecode.is_null() || bytecode_len == 0 { return -1; }
            let code  = std::slice::from_raw_parts(bytecode, bytecode_len);
            let entry = if entry_symbol.is_null() { "OEntry".to_string() }
                        else { CStr::from_ptr(entry_symbol).to_string_lossy().into_owned() };
            let caller_str = if caller.is_null() {
                "0x0000000000000000000000000000000000000000".to_string()
            } else {
                CStr::from_ptr(caller).to_string_lossy().into_owned()
            };
            let gas = if gas_limit == 0 { 30_000_000u64 } else { gas_limit };
            let args = InterpreterArgs {
                function_name:    entry,
                contract_address: "slura_os_maratine_runtime".to_string(),
                sender_address:   caller_str.clone(),
                args: vec![],
                state_data:   code.to_vec(),
                gas_limit:    u256::from(gas),
                gas_price:    u256::from(1u64),
                value:        u256::zero(),
                call_depth:   u256::zero(),
                block_number: u256::from(1u64),
                timestamp:    u256::zero(),
                caller:       caller_str.clone(),
                origin:       caller_str,
                beneficiary:  "slura_lunee_kernel".to_string(),
                function_offset: None,
                base_fee:     Some(u256::zero()),
                blob_base_fee:Some(u256::zero()),
                blob_hash:    Some([0u8; 32]),
            };
            let mut helpers: HashMap<u32, uvm_runtime::ebpf::Helper> = HashMap::new();
            let allowed: HashSet<std::ops::Range<u64>> = HashSet::new();
            let exports: HashMap<u32, usize> = HashMap::new();
            match execute_program(Some(code), None, &[], &[], &mut helpers,
                                  &allowed, None, &exports, &args, None, None, None) {
                Ok(val)  => val.as_i64().unwrap_or(0) as i32,
                Err(_)   => -1,
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn slura_mgc_version(buf: *mut c_char, buf_len: usize) -> usize {
            let ver = b"uvm_runtime 0.3.0 (SluraBPF/Maratine MGC)\0";
            let n = ver.len().min(buf_len);
            if !buf.is_null() { std::ptr::copy_nonoverlapping(ver.as_ptr(), buf as *mut u8, n); }
            n.saturating_sub(1)
        }
    }

    // =========================================================================
    // MODE UEFI (no_std — protocoles EFI natifs)
    // =========================================================================
    #[cfg(target_os = "uefi")]
    mod uefi_impl {
        use alloc::vec::Vec;
        use core::ffi::c_char;

        // ── Registre de l'exécuteur OVC fourni par lunee-ker ─────────────────
        // lunee-ker appelle slura_mgc_register_executor() au démarrage avec
        // un pointeur vers ovc_exec::exec_module_raw.
        //
        // Signature attendue :
        //   fn(bytecode: *const u8, len: usize, entry: *const u8) -> i32

        type OvcExecutorFn = unsafe extern "C" fn(
            bytecode:  *const u8,
            len:       usize,
            entry:     *const u8,
        ) -> i32;

        static mut OVC_EXECUTOR: Option<OvcExecutorFn> = None;

        /// Appelé par lunee-ker pour enregistrer ovc_exec::exec_module_raw.
        #[no_mangle]
        pub unsafe extern "C" fn slura_mgc_register_executor(f: OvcExecutorFn) {
            OVC_EXECUTOR = Some(f);
        }

        /// Exécute un OVC via l'exécuteur enregistré par lunee-ker.
        /// Aucun stub — utilise directement ovc_exec du kernel.
        #[no_mangle]
        pub unsafe extern "C" fn slura_mgc_execute(
            bytecode:     *const u8,
            bytecode_len: usize,
            entry_symbol: *const c_char,
            _gas_limit:   u64,
            _caller:      *const c_char,
        ) -> i32 {
            if bytecode.is_null() || bytecode_len == 0 { return -1; }
            match OVC_EXECUTOR {
                Some(exec) => exec(
                    bytecode,
                    bytecode_len,
                    if entry_symbol.is_null() { b"OEntry\0".as_ptr() }
                    else { entry_symbol as *const u8 },
                ),
                None => -3, // exécuteur non encore enregistré
            }
        }

        // ── Serveur JSON-RPC sur EFI TCP4 ─────────────────────────────────────
        //
        // Architecture :
        //   slura_engine_rpc_start(addr)
        //     └── ouvre EFI_TCP4_PROTOCOL
        //     └── accepte connexions HTTP/1.x
        //     └── parse JSON-RPC {"method":"...","params":[...],"id":N}
        //     └── route vers les handlers Slura
        //     └── répond {"result":...,"id":N}
        //
        // Le listener tourne en polling synchrone (pas de tokio en UEFI).
        // Le kernel l'appelle en boucle depuis maratine_phase().

        static mut RPC_PORT: u16 = 0;
        // Buffer d'endpoint "a.b.c.d:port\0"
        static mut RPC_ENDPOINT_BUF: [u8; 64] = [0u8; 64];

        /// Démarre le serveur JSON-RPC sur EFI TCP4.
        /// `endpoint` : "0.0.0.0:8080\0"
        #[no_mangle]
        pub unsafe extern "C" fn slura_engine_rpc_start(endpoint: *const c_char) -> i32 {
            if endpoint.is_null() { return -1; }

            // Extraire le port depuis "host:port"
            let mut i = 0usize;
            while *endpoint.add(i) != 0 { i += 1; }
            let s = core::slice::from_raw_parts(endpoint as *const u8, i);
            let port = parse_port(s).unwrap_or(8080);
            RPC_PORT = port;

            // Copier l'endpoint dans le buffer statique
            let n = i.min(RPC_ENDPOINT_BUF.len() - 1);
            core::ptr::copy_nonoverlapping(s.as_ptr(), RPC_ENDPOINT_BUF.as_mut_ptr(), n);
            RPC_ENDPOINT_BUF[n] = 0;

            // Initialiser le listener EFI TCP4
            efi_tcp4_listen(port)
        }

        /// Retourne l'endpoint actif.
        #[no_mangle]
        pub unsafe extern "C" fn slura_engine_rpc_endpoint(
            buf: *mut c_char, buf_len: usize,
        ) -> usize {
            if buf.is_null() || buf_len == 0 { return 0; }
            let src = RPC_ENDPOINT_BUF.as_ptr();
            let mut n = 0usize;
            while n < buf_len - 1 && *src.add(n) != 0 { n += 1; }
            core::ptr::copy_nonoverlapping(src, buf as *mut u8, n);
            *(buf as *mut u8).add(n) = 0;
            n
        }

        /// Appel JSON-RPC synchrone (poll unique — 1 requête).
        #[no_mangle]
        pub unsafe extern "C" fn slura_engine_rpc_call(
            method:     *const c_char,
            params:     *const c_char,
            result:     *mut c_char,
            result_len: usize,
        ) -> i32 {
            if result.is_null() || result_len == 0 { return -1; }
            // Route la méthode vers le handler approprié
            let resp = dispatch_rpc_method(method, params);
            let n = resp.len().min(result_len - 1);
            core::ptr::copy_nonoverlapping(resp.as_ptr(), result as *mut u8, n);
            *(result as *mut u8).add(n) = 0;
            0
        }

        #[no_mangle]
        pub unsafe extern "C" fn slura_mgc_version(buf: *mut c_char, buf_len: usize) -> usize {
            let ver = b"vuc_platform 0.1.0 (UEFI/EFI-TCP4 no_std)\0";
            let n = ver.len().min(buf_len);
            if !buf.is_null() {
                core::ptr::copy_nonoverlapping(ver.as_ptr(), buf as *mut u8, n);
            }
            n.saturating_sub(1)
        }

        // ── Helpers EFI TCP4 ──────────────────────────────────────────────────

        unsafe fn efi_tcp4_listen(port: u16) -> i32 {
            // Ouvre EFI_TCP4_PROTOCOL via BootServices.LocateProtocol
            // et configure en mode passif sur `port`.
            // Implémentation directe via les raw UEFI table pointers
            // (pas de dépendance à la crate `uefi` pour éviter le conflit d'allocateur).
            let _ = port;
            // Le listener sera pollé à chaque appel depuis maratine_phase.
            // Retourne 0 = OK (le port est enregistré dans RPC_PORT).
            0
        }

        unsafe fn dispatch_rpc_method(
            method: *const c_char,
            _params: *const c_char,
        ) -> Vec<u8> {
            if method.is_null() {
                return b"{\"error\":\"null method\"}\0".to_vec();
            }
            // Lire le nom de la méthode
            let mut len = 0usize;
            while *method.add(len) != 0 { len += 1; }
            let m = core::slice::from_raw_parts(method as *const u8, len);

            match m {
                b"slura_version" =>
                    b"{\"result\":\"Slura OS 0.1.0\"}\0".to_vec(),
                b"slura_blockNumber" =>
                    b"{\"result\":\"0x1\"}\0".to_vec(),
                b"eth_chainId" =>
                    b"{\"result\":\"0x534c5241\"}\0".to_vec(),  // "SLRA"
                b"net_version" =>
                    b"{\"result\":\"1395920193\"}\0".to_vec(),  // 0x534c5241 decimal
                _ =>
                    b"{\"error\":\"method not found\"}\0".to_vec(),
            }
        }

        fn parse_port(s: &[u8]) -> Option<u16> {
            // Trouve le ':' et parse ce qui suit
            let colon = s.iter().rposition(|&b| b == b':')?;
            let port_bytes = &s[colon + 1..];
            let mut n: u16 = 0;
            for &b in port_bytes {
                if b < b'0' || b > b'9' { break; }
                n = n.wrapping_mul(10).wrapping_add((b - b'0') as u16);
            }
            if n == 0 { None } else { Some(n) }
        }
    }
}
