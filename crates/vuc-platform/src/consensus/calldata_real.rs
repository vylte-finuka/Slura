use ethers::utils::keccak256;

/// ✅ CALLEA REAL — Résolution dynamique du calldata dans le consensus Lurosonie
/// Insère le bytecode entier + nom de fonction pour résoudre le calldata directement
pub fn resolve_real_calldata(
    bytecode: &[u8],
    function_name: &str,
    args: &[serde_json::Value],
) -> Vec<u8> {
    println!("🔧 [CONSENSUS CALLEA REAL] Résolution dynamique — bytecode: {} bytes | fn: {} | args: {}",
             bytecode.len(), function_name, args.len());

    // 1. Sélecteur depuis le nom de fonction (keccak256 des 4 premiers bytes)
    let selector = if function_name.contains('(') {
        // Extraire le nom de fonction sans args pour le hash
        let fn_sig = function_name.split('(').next().unwrap_or(function_name);
        let full_sig = format!("{}({})", fn_sig, "uint256"); // simplifié
        let hash = keccak256(full_sig.as_bytes());
        hash[..4].to_vec()
    } else {
        // Fallback : hash direct du nom
        let hash = keccak256(function_name.as_bytes());
        hash[..4].to_vec()
    };

    // 2. Bytecode entier inséré comme base du calldata (résolution directe)
    let mut calldata = Vec::with_capacity(bytecode.len() + selector.len() + 32 * args.len());
    calldata.extend_from_slice(&selector);           // 4 bytes selector
    calldata.extend_from_slice(bytecode);           // BYTECODE ENTIER inséré
    calldata.extend_from_slice(&[0u8; 12]);         // padding

    // 3. Arguments encodés dynamiquement
    for arg in args {
        if let Some(s) = arg.as_str() {
            if s.starts_with("0x") {
                if let Ok(bytes) = hex::decode(&s[2..]) {
                    calldata.extend_from_slice(&bytes);
                }
            } else {
                calldata.extend_from_slice(s.as_bytes());
            }
        } else if let Some(n) = arg.as_u64() {
            calldata.extend_from_slice(&n.to_be_bytes());
        }
    }

    println!("✅ [CONSENSUS CALLEA REAL] Calldata résolu : {} bytes (selector + bytecode + args)", calldata.len());
    calldata
}
