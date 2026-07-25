//! Encodeurs PNG et AVI purs (no_std, aucune dépendance externe) pour le
//! widget de capture ShiCamera (ShiLooker). Aucun codec/compression réelle
//! n'est requise pour des fichiers VALIDES : PNG autorise des blocs DEFLATE
//! "stored" (non compressés, légaux dans le format) et AVI/BI_RGB est par
//! définition non compressé — donc ces encodeurs produisent de VRAIS
//! fichiers lisibles par n'importe quel lecteur standard, juste volumineux,
//! honnête reflet de ce qui est réellement implémentable ici (pas de H.264,
//! pas de zlib deflate réel — décision produit assumée, voir le widget).

use alloc::vec::Vec;

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    const MODULO: u32 = 65521;
    for &byte in data {
        a = (a + byte as u32) % MODULO;
        b = (b + a) % MODULO;
    }
    (b << 16) | a
}

fn png_chunk(out: &mut Vec<u8>, tag: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let start = out.len();
    out.extend_from_slice(tag);
    out.extend_from_slice(data);
    let crc = crc32(&out[start..]);
    out.extend_from_slice(&crc.to_be_bytes());
}

/// Enveloppe zlib avec des blocs DEFLATE "stored" (BTYPE=00, non compressés) —
/// représentation 100% légale du format DEFLATE (RFC 1951 §3.2.4), juste sans
/// gain de taille. `IDAT` reste un vrai flux zlib valide décodable partout.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + (data.len() / 65535 + 1) * 5 + 6);
    out.push(0x78);
    out.push(0x01);
    let n = data.len();
    if n == 0 {
        out.push(1);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0xFFFFu16.to_le_bytes());
    }
    let mut i = 0;
    while i < n {
        let remaining = n - i;
        let block_len = remaining.min(65535);
        let is_final = (i + block_len) >= n;
        out.push(if is_final { 1 } else { 0 });
        let len = block_len as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(&data[i..i + block_len]);
        i += block_len;
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

/// Encode une image RGBA8 (row-major, top-down, 4 octets/pixel R,G,B,A) en
/// un vrai fichier PNG (IHDR + IDAT stored-deflate + IEND).
pub fn png_encode(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.push(8); // profondeur 8 bits/canal
    ihdr.push(6); // type couleur 6 = RGBA
    ihdr.push(0);
    ihdr.push(0);
    ihdr.push(0);
    png_chunk(&mut out, b"IHDR", &ihdr);

    let stride = width as usize * 4;
    let mut raw = Vec::with_capacity((stride + 1) * height as usize);
    for y in 0..height as usize {
        raw.push(0u8); // filtre "None" par scanline
        let start = y * stride;
        raw.extend_from_slice(&rgba[start..start + stride]);
    }
    let compressed = zlib_stored(&raw);
    png_chunk(&mut out, b"IDAT", &compressed);
    png_chunk(&mut out, b"IEND", &[]);
    out
}

fn riff_chunk(out: &mut Vec<u8>, tag: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(tag);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    if data.len() % 2 == 1 {
        out.push(0);
    }
}

/// (largeur du DIB paddée à 4 octets, taille totale d'une frame BGR paddée)
pub fn avi_frame_geometry(width: u32, height: u32) -> (usize, usize) {
    let row_bytes = width as usize * 3;
    let padded_row = (row_bytes + 3) & !3;
    (padded_row, padded_row * height as usize)
}

/// Assemble un fichier AVI (RIFF, flux vidéo unique BI_RGB non compressé,
/// frames bottom-up déjà préparées par l'appelant via avi_frame_geometry).
pub fn avi_encode(width: u32, height: u32, fps: u32, frames_bgr: &[Vec<u8>]) -> Vec<u8> {
    let frame_count = frames_bgr.len() as u32;
    let (_padded_row, frame_size) = avi_frame_geometry(width, height);
    let frame_size = frame_size as u32;
    let fps = fps.max(1);

    let mut avih = Vec::with_capacity(56);
    avih.extend_from_slice(&(1_000_000u32 / fps).to_le_bytes());
    avih.extend_from_slice(&(frame_size.saturating_mul(fps)).to_le_bytes());
    avih.extend_from_slice(&0u32.to_le_bytes());
    avih.extend_from_slice(&0x10u32.to_le_bytes()); // AVIF_HASINDEX
    avih.extend_from_slice(&frame_count.to_le_bytes());
    avih.extend_from_slice(&0u32.to_le_bytes());
    avih.extend_from_slice(&1u32.to_le_bytes()); // 1 flux
    avih.extend_from_slice(&frame_size.to_le_bytes());
    avih.extend_from_slice(&width.to_le_bytes());
    avih.extend_from_slice(&height.to_le_bytes());
    avih.extend_from_slice(&[0u8; 16]);

    let mut strh = Vec::with_capacity(56);
    strh.extend_from_slice(b"vids");
    strh.extend_from_slice(b"DIB ");
    strh.extend_from_slice(&0u32.to_le_bytes());
    strh.extend_from_slice(&0u16.to_le_bytes());
    strh.extend_from_slice(&0u16.to_le_bytes());
    strh.extend_from_slice(&0u32.to_le_bytes());
    strh.extend_from_slice(&1u32.to_le_bytes());
    strh.extend_from_slice(&fps.to_le_bytes());
    strh.extend_from_slice(&0u32.to_le_bytes());
    strh.extend_from_slice(&frame_count.to_le_bytes());
    strh.extend_from_slice(&frame_size.to_le_bytes());
    strh.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    strh.extend_from_slice(&0u32.to_le_bytes());
    strh.extend_from_slice(&0i16.to_le_bytes());
    strh.extend_from_slice(&0i16.to_le_bytes());
    strh.extend_from_slice(&(width as i16).to_le_bytes());
    strh.extend_from_slice(&(height as i16).to_le_bytes());

    let mut strf = Vec::with_capacity(40);
    strf.extend_from_slice(&40u32.to_le_bytes());
    strf.extend_from_slice(&(width as i32).to_le_bytes());
    strf.extend_from_slice(&(height as i32).to_le_bytes());
    strf.extend_from_slice(&1u16.to_le_bytes());
    strf.extend_from_slice(&24u16.to_le_bytes());
    strf.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB
    strf.extend_from_slice(&frame_size.to_le_bytes());
    strf.extend_from_slice(&0i32.to_le_bytes());
    strf.extend_from_slice(&0i32.to_le_bytes());
    strf.extend_from_slice(&0u32.to_le_bytes());
    strf.extend_from_slice(&0u32.to_le_bytes());

    let mut strl_inner = Vec::new();
    riff_chunk(&mut strl_inner, b"strh", &strh);
    riff_chunk(&mut strl_inner, b"strf", &strf);
    let mut strl_list = Vec::new();
    strl_list.extend_from_slice(b"LIST");
    strl_list.extend_from_slice(&((4 + strl_inner.len()) as u32).to_le_bytes());
    strl_list.extend_from_slice(b"strl");
    strl_list.extend_from_slice(&strl_inner);

    let mut hdrl_inner = Vec::new();
    riff_chunk(&mut hdrl_inner, b"avih", &avih);
    hdrl_inner.extend_from_slice(&strl_list);
    let mut hdrl_list = Vec::new();
    hdrl_list.extend_from_slice(b"LIST");
    hdrl_list.extend_from_slice(&((4 + hdrl_inner.len()) as u32).to_le_bytes());
    hdrl_list.extend_from_slice(b"hdrl");
    hdrl_list.extend_from_slice(&hdrl_inner);

    let mut movi_inner = Vec::new();
    let mut idx1 = Vec::new();
    let mut rel_offset: u32 = 4; // relatif au début des données de "movi" (après le fourcc)
    for frame in frames_bgr {
        let before = movi_inner.len();
        riff_chunk(&mut movi_inner, b"00db", frame);
        let written = (movi_inner.len() - before) as u32;
        idx1.extend_from_slice(b"00db");
        idx1.extend_from_slice(&0x10u32.to_le_bytes()); // AVIIF_KEYFRAME
        idx1.extend_from_slice(&rel_offset.to_le_bytes());
        idx1.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        rel_offset += written;
    }
    let mut movi_list = Vec::new();
    movi_list.extend_from_slice(b"LIST");
    movi_list.extend_from_slice(&((4 + movi_inner.len()) as u32).to_le_bytes());
    movi_list.extend_from_slice(b"movi");
    movi_list.extend_from_slice(&movi_inner);

    let mut idx1_chunk = Vec::new();
    riff_chunk(&mut idx1_chunk, b"idx1", &idx1);

    let mut riff_inner = Vec::new();
    riff_inner.extend_from_slice(b"AVI ");
    riff_inner.extend_from_slice(&hdrl_list);
    riff_inner.extend_from_slice(&movi_list);
    riff_inner.extend_from_slice(&idx1_chunk);

    let mut out = Vec::new();
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(riff_inner.len() as u32).to_le_bytes());
    out.extend_from_slice(&riff_inner);
    out
}
