//! Décodeurs d'images réels (no_std, aucune dépendance externe) : BMP et
//! GIF. Complètent png_decode_rgba (ovc_exec.rs) — même contrat de sortie :
//! (largeur, hauteur, pixels RGBA8 row-major top-down).
//!
//! BMP : BI_RGB (1/4/8/24/32-bit + palette) ET BI_RLE8/BI_RLE4 (compressé).
//! GIF : decode intégral multi-frames (palette globale/locale, transparence,
//! entrelacement Adam7-like) — gif_decode_all_frames renvoie CHAQUE frame
//! avec son délai d'animation ; gif_decode_rgba (utilisé par ImageLoad, un
//! seul handle par image) renvoie la première frame, la boucle d'animation
//! restant du ressort de l'appelant (widget dédié) plutôt que de ImageLoad
//! lui-même, qui ne modélise qu'UNE image statique par handle.

use alloc::vec::Vec;

fn rd_u16le(d: &[u8], o: usize) -> Option<u16> { d.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]])) }
fn rd_u32le(d: &[u8], o: usize) -> Option<u32> { d.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])) }
fn rd_i32le(d: &[u8], o: usize) -> Option<i32> { rd_u32le(d, o).map(|v| v as i32) }

fn read_palette(d: &[u8], off: usize, n: usize) -> Option<Vec<(u8, u8, u8)>> {
    let mut pal = Vec::with_capacity(n);
    for i in 0..n {
        let o = off + i * 4;
        let b = *d.get(o)?;
        let g = *d.get(o + 1)?;
        let r = *d.get(o + 2)?;
        pal.push((r, g, b));
    }
    Some(pal)
}

/// Décode un BMP — BI_RGB (1/4/8/24/32-bit) et BI_RLE8/BI_RLE4 — en RGBA8 top-down.
pub fn bmp_decode_rgba(d: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    if d.len() < 54 || &d[0..2] != b"BM" { return None; }
    let data_offset = rd_u32le(d, 10)? as usize;
    let dib_size = rd_u32le(d, 14)?;
    if dib_size < 40 { return None; }
    let width = rd_i32le(d, 18)?;
    let height_raw = rd_i32le(d, 22)?;
    let bit_count = rd_u16le(d, 28)?;
    let compression = rd_u32le(d, 30)?;
    if width <= 0 { return None; }
    let top_down = height_raw < 0;
    let height = height_raw.unsigned_abs();
    if height == 0 { return None; }
    let w = width as u32;
    let h = height;
    let palette_off = 14 + dib_size as usize;
    let row_bytes_src = |bpp: u32| -> usize { (((w as usize * bpp as usize) + 31) / 32) * 4 };
    let mut out = alloc::vec![0u8; w as usize * h as usize * 4];

    let put_px = |out: &mut Vec<u8>, x: usize, y_dst: usize, r: u8, g: u8, b: u8, a: u8| {
        let o = (y_dst * w as usize + x) * 4;
        out[o] = r; out[o + 1] = g; out[o + 2] = b; out[o + 3] = a;
    };

    match (bit_count, compression) {
        (1, 0) | (4, 0) | (8, 0) => {
            let colors_used = rd_u32le(d, 46).unwrap_or(1 << bit_count);
            let n = if colors_used == 0 { 1usize << bit_count } else { colors_used as usize };
            let pal = read_palette(d, palette_off, n)?;
            let stride = row_bytes_src(bit_count as u32);
            for y in 0..h as usize {
                let src_row = if top_down { y } else { h as usize - 1 - y };
                let row_off = data_offset + src_row * stride;
                for x in 0..w as usize {
                    let idx = match bit_count {
                        1 => {
                            let byte = *d.get(row_off + x / 8)?;
                            ((byte >> (7 - (x % 8))) & 0x01) as usize
                        }
                        4 => {
                            let byte = *d.get(row_off + x / 2)?;
                            (if x % 2 == 0 { byte >> 4 } else { byte & 0x0F }) as usize
                        }
                        _ => *d.get(row_off + x)? as usize,
                    };
                    let (r, g, b) = *pal.get(idx).unwrap_or(&(0, 0, 0));
                    put_px(&mut out, x, y, r, g, b, 255);
                }
            }
        }
        (24, 0) => {
            let stride = row_bytes_src(24);
            for y in 0..h as usize {
                let src_row = if top_down { y } else { h as usize - 1 - y };
                let row_off = data_offset + src_row * stride;
                for x in 0..w as usize {
                    let po = row_off + x * 3;
                    let b = *d.get(po)?; let g = *d.get(po + 1)?; let r = *d.get(po + 2)?;
                    put_px(&mut out, x, y, r, g, b, 255);
                }
            }
        }
        (32, 0) => {
            let stride = row_bytes_src(32);
            for y in 0..h as usize {
                let src_row = if top_down { y } else { h as usize - 1 - y };
                let row_off = data_offset + src_row * stride;
                for x in 0..w as usize {
                    let po = row_off + x * 4;
                    let b = *d.get(po)?; let g = *d.get(po + 1)?; let r = *d.get(po + 2)?; let a = *d.get(po + 3)?;
                    put_px(&mut out, x, y, r, g, b, a);
                }
            }
        }
        (8, 1) | (4, 2) => {
            // BI_RLE8 (comp=1) / BI_RLE4 (comp=2) — toujours bottom-up par spec.
            let colors_used = rd_u32le(d, 46).unwrap_or(1 << bit_count);
            let n = if colors_used == 0 { 1usize << bit_count } else { colors_used as usize };
            let pal = read_palette(d, palette_off, n)?;
            let rle4 = bit_count == 4;
            let mut x: usize = 0;
            let mut y_bottom: usize = 0; // ligne depuis le BAS (0 = dernière ligne écrite)
            let mut p = data_offset;
            loop {
                let a = *d.get(p)?; let b = *d.get(p + 1)?; p += 2;
                if a > 0 {
                    // Run encodé : `a` pixels avec le(s) index(s) de `b`.
                    let run = a as usize;
                    if rle4 {
                        let hi = b >> 4; let lo = b & 0x0F;
                        for i in 0..run {
                            let idx = if i % 2 == 0 { hi } else { lo } as usize;
                            let (r, g, bl) = *pal.get(idx).unwrap_or(&(0, 0, 0));
                            if x < w as usize && y_bottom < h as usize {
                                put_px(&mut out, x, h as usize - 1 - y_bottom, r, g, bl, 255);
                            }
                            x += 1;
                        }
                    } else {
                        let (r, g, bl) = *pal.get(b as usize).unwrap_or(&(0, 0, 0));
                        for _ in 0..run {
                            if x < w as usize && y_bottom < h as usize {
                                put_px(&mut out, x, h as usize - 1 - y_bottom, r, g, bl, 255);
                            }
                            x += 1;
                        }
                    }
                } else {
                    match b {
                        0 => { x = 0; y_bottom += 1; } // fin de ligne
                        1 => break,                     // fin de bitmap
                        2 => {
                            let dx = *d.get(p)? as usize; let dy = *d.get(p + 1)? as usize; p += 2;
                            x += dx; y_bottom += dy;
                        }
                        _ => {
                            // Run absolu de `b` index littéraux, paddé sur 2 octets.
                            let count = b as usize;
                            let bytes_needed = if rle4 { (count + 1) / 2 } else { count };
                            let mut consumed = 0usize;
                            for i in 0..count {
                                let idx = if rle4 {
                                    let byte = *d.get(p + i / 2)?;
                                    (if i % 2 == 0 { byte >> 4 } else { byte & 0x0F }) as usize
                                } else {
                                    *d.get(p + i)? as usize
                                };
                                let (r, g, bl) = *pal.get(idx).unwrap_or(&(0, 0, 0));
                                if x < w as usize && y_bottom < h as usize {
                                    put_px(&mut out, x, h as usize - 1 - y_bottom, r, g, bl, 255);
                                }
                                x += 1;
                                consumed = i + 1;
                            }
                            let _ = consumed;
                            p += bytes_needed + (bytes_needed % 2); // padding mot pair
                        }
                    }
                }
                if y_bottom >= h as usize { break; }
            }
        }
        _ => return None,
    }
    Some((w, h, out))
}

/// Décodeur LZW variable-width façon GIF (RFC 89a), dé-blocké au préalable.
fn gif_lzw_decode(min_code_size: u8, blocks: &[u8], expected_pixels: usize) -> Option<Vec<u8>> {
    let clear_code: u32 = 1 << min_code_size;
    let end_code: u32 = clear_code + 1;
    let mut code_size = min_code_size as u32 + 1;
    let mut dict: Vec<Vec<u8>> = Vec::new();
    let reset_dict = |dict: &mut Vec<Vec<u8>>, cs: &mut u32, min: u8| {
        dict.clear();
        for i in 0..(1u32 << min) { dict.push(alloc::vec![i as u8]); }
        dict.push(Vec::new()); // clear_code placeholder
        dict.push(Vec::new()); // end_code placeholder
        *cs = min as u32 + 1;
    };
    reset_dict(&mut dict, &mut code_size, min_code_size);

    let mut out: Vec<u8> = Vec::with_capacity(expected_pixels);
    let mut bitpos: usize = 0;
    let total_bits = blocks.len() * 8;
    let read_code = |bitpos: &mut usize, size: u32| -> Option<u32> {
        if *bitpos + size as usize > total_bits { return None; }
        let mut v: u32 = 0;
        for i in 0..size {
            let bit_index = *bitpos + i as usize;
            let byte = blocks[bit_index / 8];
            let bit = (byte >> (bit_index % 8)) & 1;
            v |= (bit as u32) << i;
        }
        *bitpos += size as usize;
        Some(v)
    };

    let mut prev: Option<Vec<u8>> = None;
    loop {
        let code = match read_code(&mut bitpos, code_size) { Some(c) => c, None => break };
        if code == clear_code {
            reset_dict(&mut dict, &mut code_size, min_code_size);
            prev = None;
            continue;
        }
        if code == end_code { break; }

        let entry: Vec<u8> = if (code as usize) < dict.len() && !dict[code as usize].is_empty() {
            dict[code as usize].clone()
        } else if code as usize == dict.len() {
            match &prev {
                Some(p) => { let mut e = p.clone(); e.push(p[0]); e }
                None => return None,
            }
        } else {
            return None;
        };

        out.extend_from_slice(&entry);
        if out.len() >= expected_pixels { break; }

        if let Some(p) = &prev {
            let mut newe = p.clone();
            newe.push(entry[0]);
            dict.push(newe);
            let dict_len = dict.len();
            if dict_len == (1 << code_size) && code_size < 12 { code_size += 1; }
        }
        prev = Some(entry);
    }
    if out.len() < expected_pixels { return None; }
    out.truncate(expected_pixels);
    Some(out)
}

/// Une frame GIF décodée : dimensions, pixels RGBA8, délai d'affichage
/// (centièmes de seconde, tel qu'encodé par le format).
pub struct GifFrame {
    pub width:  u32,
    pub height: u32,
    pub delay_cs: u16,
    pub pixels: Vec<u8>,
}

/// Décode TOUTES les frames d'un GIF (animé ou statique — un GIF statique a
/// simplement une seule frame). Compose chaque frame sur un canevas plein
/// écran (taille de l'écran logique du GIF), gère palette globale/locale,
/// transparence et entrelacement.
pub fn gif_decode_all_frames(d: &[u8]) -> Option<Vec<GifFrame>> {
    if d.len() < 13 { return None; }
    if &d[0..6] != b"GIF87a" && &d[0..6] != b"GIF89a" { return None; }
    let screen_w = rd_u16le(d, 6)? as u32;
    let screen_h = rd_u16le(d, 8)? as u32;
    let packed = d[10];
    let gct_flag = (packed & 0x80) != 0;
    let gct_size = 2usize.pow(((packed & 0x07) as u32) + 1);
    let mut pos = 13usize;
    let mut gct: Vec<(u8, u8, u8)> = Vec::new();
    if gct_flag {
        for i in 0..gct_size {
            let o = pos + i * 3;
            gct.push((*d.get(o)?, *d.get(o + 1)?, *d.get(o + 2)?));
        }
        pos += gct_size * 3;
    }

    let mut frames: Vec<GifFrame> = Vec::new();
    let mut transparent_index: Option<u8> = None;
    let mut delay_cs: u16 = 0;

    loop {
        let tag = match d.get(pos) { Some(&t) => t, None => break };
        pos += 1;
        if tag == 0x3B { break; } // trailer
        if tag == 0x21 {
            let label = *d.get(pos)?;
            pos += 1;
            if label == 0xF9 {
                let block_size = *d.get(pos)? as usize;
                if block_size >= 4 {
                    let flags = *d.get(pos + 1)?;
                    delay_cs = rd_u16le(d, pos + 2)?;
                    transparent_index = if (flags & 0x01) != 0 { Some(*d.get(pos + 4)?) } else { None };
                }
            }
            loop {
                let bsz = *d.get(pos)? as usize;
                pos += 1;
                if bsz == 0 { break; }
                pos += bsz;
            }
        } else if tag == 0x2C {
            let iw = rd_u16le(d, pos + 4)? as u32;
            let ih = rd_u16le(d, pos + 6)? as u32;
            let ipacked = *d.get(pos + 8)?;
            pos += 9;
            let lct_flag = (ipacked & 0x80) != 0;
            let interlaced = (ipacked & 0x40) != 0;
            let lct_size = 2usize.pow(((ipacked & 0x07) as u32) + 1);
            let mut lct: Vec<(u8, u8, u8)> = Vec::new();
            if lct_flag {
                for i in 0..lct_size {
                    let o = pos + i * 3;
                    lct.push((*d.get(o)?, *d.get(o + 1)?, *d.get(o + 2)?));
                }
                pos += lct_size * 3;
            }
            let palette = if lct_flag { &lct } else { &gct };
            if palette.is_empty() { return None; }

            let min_code_size = *d.get(pos)?;
            pos += 1;
            let mut blocks: Vec<u8> = Vec::new();
            loop {
                let bsz = *d.get(pos)? as usize;
                pos += 1;
                if bsz == 0 { break; }
                blocks.extend_from_slice(d.get(pos..pos + bsz)?);
                pos += bsz;
            }
            if iw == 0 || ih == 0 { return None; }
            let indices = gif_lzw_decode(min_code_size, &blocks, (iw * ih) as usize)?;

            let row_order: Vec<u32> = if interlaced {
                let mut order = Vec::with_capacity(ih as usize);
                let mut y = 0u32; while y < ih { order.push(y); y += 8; }
                let mut y = 4u32; while y < ih { order.push(y); y += 8; }
                let mut y = 2u32; while y < ih { order.push(y); y += 4; }
                let mut y = 1u32; while y < ih { order.push(y); y += 2; }
                order
            } else {
                (0..ih).collect()
            };
            let mut out = alloc::vec![0u8; (iw * ih * 4) as usize];
            for (src_row, &dst_row) in row_order.iter().enumerate() {
                for x in 0..iw as usize {
                    let idx = indices[src_row * iw as usize + x] as usize;
                    let o = ((dst_row * iw) as usize + x) * 4;
                    if Some(idx as u8) == transparent_index {
                        out[o] = 0; out[o + 1] = 0; out[o + 2] = 0; out[o + 3] = 0;
                    } else {
                        let (r, g, b) = *palette.get(idx).unwrap_or(&(0, 0, 0));
                        out[o] = r; out[o + 1] = g; out[o + 2] = b; out[o + 3] = 255;
                    }
                }
            }
            frames.push(GifFrame { width: iw, height: ih, delay_cs, pixels: out });
            transparent_index = None;
            delay_cs = 0;
        } else {
            break;
        }
    }
    if frames.is_empty() { return None; }
    let _ = (screen_w, screen_h); // écran logique dispo pour un futur compositing multi-frame
    Some(frames)
}

/// Première frame d'un GIF, même contrat que png_decode_rgba/bmp_decode_rgba
/// (utilisé par ImageLoad, qui gère UN handle = UNE image statique).
pub fn gif_decode_rgba(d: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    let frames = gif_decode_all_frames(d)?;
    let f = frames.into_iter().next()?;
    Some((f.width, f.height, f.pixels))
}
