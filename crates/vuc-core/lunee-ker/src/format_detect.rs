//! Détection de format réelle par signature (magic bytes), no_std. Couvre
//! tous les formats listés pour EncDecProcMan — DÉTECTION uniquement pour
//! les formats sans décodeur réel dans Slura (voir DECODE_SUPPORT ci-dessous
//! pour ce qui est réellement décodable aujourd'hui : PNG/BMP/GIF images,
//! rien côté vidéo/audio — la détection de conteneur reste honnête sur ce
//! qu'elle apporte : identifier le type, pas lire les échantillons).

/// Identifiants stables (exposés côté Mara via EncDecGetFormatName /
/// EncDecCanDecode) — ordre arbitraire, ne pas réutiliser un id existant.
pub const FMT_UNKNOWN: i32 = 0;
pub const FMT_PNG:     i32 = 1;
pub const FMT_BMP:     i32 = 2;
pub const FMT_GIF:     i32 = 3;
pub const FMT_JPEG:    i32 = 4;
pub const FMT_MP4:     i32 = 5;
pub const FMT_MOV:     i32 = 6;
pub const FMT_HEIC:    i32 = 7;
pub const FMT_HEIF:    i32 = 8;
pub const FMT_MKV:     i32 = 9;
pub const FMT_WEBM:    i32 = 10;
pub const FMT_AVI:     i32 = 11;
pub const FMT_MP3:     i32 = 12;
pub const FMT_MP2:     i32 = 13;
pub const FMT_OGG:     i32 = 14;
pub const FMT_AMR:     i32 = 15;

fn has_prefix(d: &[u8], p: &[u8]) -> bool { d.len() >= p.len() && &d[..p.len()] == p }

/// Recherche une sous-séquence dans les N premiers octets (heuristique EBML
/// DocType — pas un parseur EBML complet, suffisant pour distinguer
/// Matroska/WebM par leur chaîne "matroska"/"webm" présente près du début).
fn contains_in(d: &[u8], needle: &[u8], scan_len: usize) -> bool {
    let n = d.len().min(scan_len);
    if n < needle.len() { return false; }
    d[..n].windows(needle.len()).any(|w| w == needle)
}

/// Détecte le format à partir des premiers octets du fichier. Réel : lit
/// des signatures binaires standard (pas une extension de nom de fichier).
pub fn detect_format(d: &[u8]) -> i32 {
    if d.len() < 4 { return FMT_UNKNOWN; }

    if has_prefix(d, b"\x89PNG\r\n\x1a\n") { return FMT_PNG; }
    if has_prefix(d, b"BM") { return FMT_BMP; }
    if has_prefix(d, b"GIF87a") || has_prefix(d, b"GIF89a") { return FMT_GIF; }
    if has_prefix(d, &[0xFF, 0xD8, 0xFF]) { return FMT_JPEG; }
    if has_prefix(d, b"ID3") { return FMT_MP3; }
    if has_prefix(d, b"OggS") { return FMT_OGG; }
    if has_prefix(d, b"#!AMR") { return FMT_AMR; }

    if d.len() >= 12 && &d[4..8] == b"ftyp" {
        let brand = &d[8..12.min(d.len())];
        return match brand {
            b"heic" | b"heix" | b"heim" | b"heis" => FMT_HEIC,
            b"mif1" | b"msf1" | b"hevc" | b"hevx" => FMT_HEIF,
            b"qt  " => FMT_MOV,
            _ => FMT_MP4, // isom/mp41/mp42/avc1/iso2/... — famille MP4 par défaut
        };
    }

    if has_prefix(d, b"RIFF") && d.len() >= 12 {
        if &d[8..12] == b"AVI " { return FMT_AVI; }
    }

    if has_prefix(d, &[0x1A, 0x45, 0xDF, 0xA3]) {
        // EBML — Matroska (.mkv) ou WebM (.webm), distingués par le DocType
        // (chaîne ASCII "matroska"/"webm" présente tôt dans le flux EBML).
        if contains_in(d, b"webm", 512) { return FMT_WEBM; }
        if contains_in(d, b"matroska", 512) { return FMT_MKV; }
        return FMT_MKV; // EBML sans DocType lisible dans la fenêtre : par défaut Matroska
    }

    // MPEG audio (MP2/MP3 sans tag ID3) : frame sync 11 bits à 1, puis les
    // bits Layer (17-18) distinguent Layer III (MP3, 01) de Layer II (MP2, 10).
    if d.len() >= 2 && d[0] == 0xFF && (d[1] & 0xE0) == 0xE0 {
        let layer_bits = (d[1] >> 1) & 0x03;
        return match layer_bits {
            0b01 => FMT_MP3,
            0b10 => FMT_MP2,
            _ => FMT_UNKNOWN,
        };
    }

    FMT_UNKNOWN
}

/// Niveau de support réel pour un format détecté : 2 = décodage complet
/// (image affichable), 1 = détection/identification seulement (conteneur
/// reconnu, échantillons non extraits), 0 = non reconnu.
pub fn decode_support(fmt: i32) -> i32 {
    match fmt {
        FMT_PNG | FMT_BMP | FMT_GIF => 2,
        FMT_JPEG | FMT_MP4 | FMT_MOV | FMT_HEIC | FMT_HEIF | FMT_MKV | FMT_WEBM
            | FMT_AVI | FMT_MP3 | FMT_MP2 | FMT_OGG | FMT_AMR => 1,
        _ => 0,
    }
}

/// Nom humain stable pour l'UI (ShiLooker) — ASCII uniquement (police sans
/// glyphes étendus, voir contrainte établie ce projet).
pub fn format_name(fmt: i32) -> &'static str {
    match fmt {
        FMT_PNG  => "PNG",
        FMT_BMP  => "BMP",
        FMT_GIF  => "GIF",
        FMT_JPEG => "JPEG",
        FMT_MP4  => "MP4",
        FMT_MOV  => "MOV",
        FMT_HEIC => "HEIC",
        FMT_HEIF => "HEIF",
        FMT_MKV  => "MKV",
        FMT_WEBM => "WebM",
        FMT_AVI  => "AVI",
        FMT_MP3  => "MP3",
        FMT_MP2  => "MP2",
        FMT_OGG  => "OGG",
        FMT_AMR  => "AMR (codec appel cellulaire)",
        _ => "Inconnu",
    }
}
