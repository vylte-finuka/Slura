//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee — fenêtres applicatives (bureau à fenêtres, jalon 1 étape 4) ___

//! Une app lancée par-dessus le bureau ShiLauncher tourne dans son propre buffer
//! offscreen (`content_w`×`content_h`, stride = `content_w`) au lieu de partager le
//! framebuffer plein écran — c'est ce qui évite qu'un `GpuFill` (ou toute autre
//! primitive plein-cadre) de l'app efface le rendu du bureau, comme observé lors
//! d'un test antérieur (deux `exec_marep` partageant encore le même framebuffer).
//!
//! Toute la logique de fenêtrage (liste des fenêtres, position/taille, hit-test,
//! déclenchement) vit côté Maratine (`LAPrevent.mara`/`TemplateView.mara`) — ce
//! module ne fournit que la structure de données et les primitives bas niveau
//! (buffer, exécution, composition), pilotées depuis `ovc_exec.rs` via les
//! builtins `DrvAPIInterCon***WindowMan...***` (liste `RUNNING_APPS` statique).

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

/// Une app lancée dans une fenêtre. `x`/`y` = coin haut-gauche de la zone de
/// CONTENU sur l'écran (hors chrome, ajouté par-dessus à l'étape 5).
pub struct RunningApp {
    pub name:      String,
    pub modules:   Vec<(String, Vec<u8>)>,
    pub x:         i32,
    pub y:         i32,
    pub content_w: i32,
    pub content_h: i32,
    pub buffer:    Vec<u32>, // taille content_w*content_h, stride == content_w
}

impl RunningApp {
    pub fn new(name: String, modules: Vec<(String, Vec<u8>)>, x: i32, y: i32, content_w: i32, content_h: i32) -> Self {
        let buffer = alloc::vec![0u32; (content_w * content_h).max(0) as usize];
        Self { name, modules, x, y, content_w, content_h, buffer }
    }

    /// Références `&[(&str, &[u8])]` pour `ovc_exec::exec_marep` — même pattern
    /// que `mod_refs` dans `kernel_runtime.rs` pour les modules du bureau.
    pub fn mod_refs(&self) -> Vec<(&str, &[u8])> {
        self.modules.iter().map(|(n, b)| (n.as_str(), b.as_slice())).collect()
    }

    /// Redimensionne la fenêtre (clampé à un minimum utilisable) et réalloue son
    /// buffer — perd le contenu précédent, redessiné entièrement au tick suivant
    /// via `WindowManRenderAndComposite`.
    pub fn resize(&mut self, w: i32, h: i32) {
        self.content_w = w.max(100);
        self.content_h = h.max(80);
        self.buffer = alloc::vec![0u32; (self.content_w * self.content_h) as usize];
    }

    /// Recopie `self.buffer` dans `backbuffer` (stride `dst_stride`, hauteur
    /// `dst_h`) à la position `(x, y)` de la fenêtre, ligne par ligne, clampé
    /// aux bords de l'écran — la fenêtre peut être partiellement hors-cadre
    /// (ex. pendant un déplacement, étape 6) sans jamais écrire hors de
    /// `backbuffer`.
    pub fn blit_into(&self, backbuffer: &mut [u32], dst_stride: i32, dst_w: i32, dst_h: i32) {
        if self.content_w <= 0 || self.content_h <= 0 { return; }
        for row in 0..self.content_h {
            let dst_y = self.y + row;
            if dst_y < 0 || dst_y >= dst_h { continue; }
            let src_off = (row * self.content_w) as usize;
            let src_row = &self.buffer[src_off..src_off + self.content_w as usize];

            let dst_x0 = self.x.max(0);
            let dst_x1 = (self.x + self.content_w).min(dst_w);
            if dst_x1 <= dst_x0 { continue; }

            let src_x0 = (dst_x0 - self.x) as usize;
            let count  = (dst_x1 - dst_x0) as usize;
            let dst_off = (dst_y * dst_stride + dst_x0) as usize;

            backbuffer[dst_off..dst_off + count]
                .copy_from_slice(&src_row[src_x0..src_x0 + count]);
        }
    }
}
