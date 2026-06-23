pub mod consensus;
pub mod slurachain_rpc_service;
pub mod operator;

// ── Exports C-ABI pour le kernel Lunée (platform_bridge) ─────────────────────
//
// Architecture :
//   lunee-ker (no_std UEFI) → extern "C" → vuc_platform::kernel_abi
//                                              ├── execute_program (uvm_runtime)
//                                              └── ServerBuilder (jsonrpsee)
//
// Les fonctions ci-dessous utilisent les patterns de engine_platform.rs :
//   engine_platform.rs :  use uvm_runtime::interpreter::execute_program;
//   engine_platform.rs :  use uvm_runtime::interpreter::InterpreterArgs;
//   engine_platform.rs :  EnginePlatform { rpc_service, vm, ... }
//
// Deux phases :
//   Phase UEFI (no_std)  : le stub dans efi_manager.cpp renvoie -2 (not ready)
//   Phase OS   (std)     : cette implémentation s'exécute via slura_mgc_execute

pub mod kernel_abi {
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;
    use std::sync::{Arc, Mutex, OnceLock};

    // ── Imports engine_platform (Node RPC SluraChain) ─────────────────────────
    use jsonrpsee_server::{RpcModule, ServerBuilder};

    // ── Imports interpreter (Maratine Graphical Compute / UVM) ───────────────
    // Mirrors engine_platform.rs:
    //   use uvm_runtime::interpreter::execute_program;
    //   use uvm_runtime::interpreter::InterpreterArgs;
    use uvm_runtime::interpreter::{execute_program, InterpreterArgs};
    use hashbrown::{HashMap, HashSet};
    use primitive_types::U256 as u256;

    // ── État global du nœud RPC ───────────────────────────────────────────────
    static RPC_ENDPOINT: OnceLock<String> = OnceLock::new();

    // ── Node RPC SluraChain — applique engine_platform.rs ────────────────────
    //
    // Pattern engine_platform.rs :
    //   let rpc_service = slurachainRpcService::new(default_port, ...)
    //   ServerBuilder::default().build(&addr).await?
    //
    // Ici : version synchrone via tokio::runtime::Runtime::new().block_on(...)

    /// Démarre le nœud JSON-RPC SluraChain en arrière-plan.
    /// `endpoint` : C-string null-terminated, ex: "0.0.0.0:8080\0"
    #[no_mangle]
    pub unsafe extern "C" fn slura_engine_rpc_start(endpoint: *const c_char) -> i32 {
        if endpoint.is_null() { return -1; }
        let addr = match CStr::from_ptr(endpoint).to_str() {
            Ok(s) => s.to_owned(),
            Err(_) => return -2,
        };

        let addr_clone = addr.clone();
        std::thread::spawn(move || {
            match tokio::runtime::Runtime::new() {
                Ok(rt) => rt.block_on(async move {
                    match ServerBuilder::default().build(&addr_clone).await {
                        Ok(server) => {
                            if let Ok(local) = server.local_addr() {
                                let ep = local.to_string();
                                RPC_ENDPOINT.set(ep.clone()).ok();
                                tracing::info!("SluraChain RPC on {}", ep);
                            }
                            let _h = server.start(RpcModule::new(()));
                            tokio::signal::ctrl_c().await.ok();
                        }
                        Err(e) => tracing::error!("RPC start failed: {}", e),
                    }
                }),
                Err(e) => tracing::error!("tokio runtime: {}", e),
            }
        });
        0
    }

    /// Retourne l'endpoint RPC actif.
    #[no_mangle]
    pub unsafe extern "C" fn slura_engine_rpc_endpoint(
        buf: *mut c_char,
        buf_len: usize,
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

    /// Appel JSON-RPC synchrone.
    #[no_mangle]
    pub unsafe extern "C" fn slura_engine_rpc_call(
        _method:    *const c_char,
        _params:    *const c_char,
        result:     *mut c_char,
        result_len: usize,
    ) -> i32 {
        let resp = b"{}\0";
        let n = resp.len().min(result_len);
        if !result.is_null() && result_len > 0 {
            std::ptr::copy_nonoverlapping(resp.as_ptr(), result as *mut u8, n);
        }
        0
    }

    // ── Maratine Graphical Compute — applique engine_platform.rs ─────────────
    //
    // Pattern engine_platform.rs :
    //   use uvm_runtime::interpreter::execute_program;
    //   use uvm_runtime::interpreter::InterpreterArgs;
    //
    //   let args = InterpreterArgs {
    //       function_name: "OEntry".to_string(),
    //       state_data: bytecode.to_vec(),
    //       gas_limit: u256::from(30_000_000u64),
    //       ...
    //   };
    //   execute_program(Some(&bytecode), Some(&stack), &[], &[], &mut helpers,
    //                   &allowed, None, &exports, &args, storage, None, None)

    /// Exécute un programme Maratine (OVC = LLVM IR) via l'interpréteur UVM.
    /// Applique le pattern de engine_platform.rs pour InterpreterArgs + execute_program.
    #[no_mangle]
    pub unsafe extern "C" fn slura_mgc_execute(
        bytecode:     *const u8,
        bytecode_len: usize,
        entry_symbol: *const c_char,
        gas_limit:    u64,
        caller:       *const c_char,
    ) -> i32 {
        if bytecode.is_null() || bytecode_len == 0 { return -1; }

        let code = std::slice::from_raw_parts(bytecode, bytecode_len);

        // Pattern engine_platform.rs : InterpreterArgs
        let entry = if entry_symbol.is_null() {
            "OEntry".to_string()
        } else {
            CStr::from_ptr(entry_symbol).to_string_lossy().into_owned()
        };

        let caller_str = if caller.is_null() {
            "0x0000000000000000000000000000000000000000".to_string()
        } else {
            CStr::from_ptr(caller).to_string_lossy().into_owned()
        };

        let gas = if gas_limit == 0 { 30_000_000u64 } else { gas_limit };

        // ── InterpreterArgs — calqué sur engine_platform.rs ──────────────────
        let args = InterpreterArgs {
            function_name:    entry.clone(),
            contract_address: "slura_os_maratine_runtime".to_string(),
            sender_address:   caller_str.clone(),
            args:             vec![],
            state_data:       code.to_vec(),     // OVC = bytecode Maratine
            gas_limit:        u256::from(gas),
            gas_price:        u256::from(1u64),
            value:            u256::zero(),
            call_depth:       u256::zero(),
            block_number:     u256::from(1u64),
            timestamp:        u256::zero(), // pas de std::time en UEFI
            caller:           caller_str.clone(),
            origin:           caller_str,
            beneficiary:      "slura_lunee_kernel".to_string(),
            function_offset:  None,
            base_fee:         Some(u256::zero()),
            blob_base_fee:    Some(u256::zero()),
            blob_hash:        Some([0u8; 32]),
        };

        // ── execute_program — calqué sur engine_platform.rs ──────────────────
        let mut helpers: HashMap<u32, uvm_runtime::ebpf::Helper> = HashMap::new();
        let allowed: HashSet<std::ops::Range<u64>> = HashSet::new();
        let exports: HashMap<u32, usize> = HashMap::new();

        match execute_program(
            Some(code),          // prog_ = OVC Maratine
            None,                // stack_usage = calculée automatiquement
            &[],                 // mem
            &[],                 // mbuff
            &mut helpers,
            &allowed,
            None,                // ret_type
            &exports,
            &args,
            None,                // storage_manager (RocksDB facultatif en phase UEFI)
            None,                // initial_storage
            None,                // on_create2_event
        ) {
            Ok(val)  => {
                tracing::info!("[MGC] OEntry retourné: {:?}", val);
                val.as_i64().unwrap_or(0) as i32
            }
            Err(e) => {
                tracing::error!("[MGC] execute_program error: {:?}", e);
                -1
            }
        }
    }

    /// Version de l'interpréteur UVM.
    #[no_mangle]
    pub unsafe extern "C" fn slura_mgc_version(buf: *mut c_char, buf_len: usize) -> usize {
        let ver = b"uvm_runtime 0.3.0 (sluBPF / Maratine MGC via engine_platform)\0";
        let n = ver.len().min(buf_len);
        if !buf.is_null() && buf_len > 0 {
            std::ptr::copy_nonoverlapping(ver.as_ptr(), buf as *mut u8, n);
        }
        n.saturating_sub(1)
    }
}
