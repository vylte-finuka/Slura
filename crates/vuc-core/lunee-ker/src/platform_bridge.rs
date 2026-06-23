//___  Vyft Ltd __  (c) 2026  ___
// ___ Lunée Kernel — Platform Bridge ___
//
//! Types d'erreur partagés entre le kernel et le futur runtime OS.
//! Le rendu Maratine est géré directement par gop_display::execute_marep_screen.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformError {
    InvalidBinary,
    ExecutionFailed(i32),
    NotInitialized,
}

/// Configuration du nœud RPC (phase OS future).
#[derive(Debug, Clone)]
pub struct RpcNodeConfig {
    pub listen_addr: &'static str,
    pub chain_id:    u64,
    pub node_srid:   &'static str,
}

impl Default for RpcNodeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080",
            chain_id:    0x534C55,
            node_srid:   "SRID_lunee_node_001",
        }
    }
}
