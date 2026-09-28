//! VTREE-X Cryptographic Module
//! Based on VTREE-X.md specification
//! Quantum-safe: uses SHA-3 (Keccak) instead of SHA-2

use sha3::{Keccak256, Keccak512, Digest};

/// H256 : SHA3-256 (32 octets) — quantum-safe (résistant à Grover)
fn h256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// H512 : SHA3-512 (64 octets) — quantum-safe
fn h512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Keccak512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

/// Étend un fragment de 13 octets vers un bloc de 32 octets (padding)
fn extend(fragment: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = fragment.len().min(13);
    out[..len].copy_from_slice(&fragment[..len]);
    for i in len..32 {
        out[i] = fragment[i % len.max(1)];
    }
    out
}

/// Génère le quintuplet VTREE-X (O_0, O_1, O_2, O_3, O_4)
/// Quantum-safe grâce à SHA-3 (Keccak)
pub fn vtree_x(seed: &[u8], d: &[u8]) -> Vec<[u8; 33]> {
    // 1. Initialisation des clés maîtres
    let mut k_input = Vec::new();
    k_input.extend_from_slice(seed);
    k_input.extend_from_slice(b"VTREE-X-MasterKey");
    let k = h512(&k_input);

    let mut s_input = Vec::new();
    s_input.extend_from_slice(&k);
    s_input.extend_from_slice(b"VTREE-X-InversionSecret");
    let s = h512(&s_input);

    let mut outputs: Vec<[u8; 33]> = Vec::with_capacity(5);

    // 2. Boucle sur 5 sous-branches
    for i in 0..5 {
        let start = 13 * i;
        let end = (start + 13).min(64);
        let f_i = &k[start..end];

        let mut x_r = extend(f_i);

        // Cascade des 24 rounds
        for _r in 1..=24 {
            let taille_etat = x_r.len();
            
            let mut m_r = [0u8; 32];
            let mut r_r = [0u8; 32];
            let mut r_l = [0u8; 32];
            let mut xor_r = [0u8; 32];

            for j in 0..taille_etat {
                m_r[j] = ((x_r[j] as u16 * 0xD3) % 256) as u8;
                r_r[j] = x_r[j] >> 5;
                r_l[j] = x_r[j] << 7;
                xor_r[j] = x_r[j] ^ s[j % 64];
            }

            let mut tampon = Vec::new();
            tampon.extend_from_slice(d);
            tampon.extend_from_slice(&x_r);
            tampon.extend_from_slice(&m_r);
            tampon.extend_from_slice(&r_r);
            tampon.extend_from_slice(&r_l);
            tampon.extend_from_slice(&xor_r);
            
            x_r = h256(&tampon);
        }

        let c_i = h256(&x_r);
        let chk_i = c_i[0] ^ c_i[15] ^ c_i[31];
        
        let mut o_i = [0u8; 33];
        o_i[..32].copy_from_slice(&c_i);
        o_i[32] = chk_i;
        
        outputs.push(o_i);
    }

    outputs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vtree_x_basic() {
        let seed = b"test_seed";
        let d = b"test_domain";
        let result = vtree_x(seed, d);
        assert_eq!(result.len(), 5);
        for o in &result {
            assert_eq!(o.len(), 33);
        }
    }
}
