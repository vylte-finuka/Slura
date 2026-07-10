// ___ Vyft Ltd (c) 2026 ___  Wrapper freestanding autour de stb_truetype.h (public domain)
// Fournit les primitives natives stb_* que SluFontConf.slul (GlyphRasterizer/TtfParser)
// appelle via <stb_*___>. AUCUNE libc : allocateur arène + math maison (kernel UEFI no_std).
// Le dispatch ovc_exec.rs relaie <stb_*___> vers ces symboles extern "C".

#ifndef NULL
#define NULL ((void*)0)
#endif

typedef unsigned char  u8;
typedef unsigned int   u32;
typedef unsigned long long u64;

// ── Arène (intermédiaires stb) : réinitialisée à chaque rastérisation ────────
static u8  g_arena[1u << 20];   // 1 Mo
static u64 g_arena_off = 0;
static void* arena_alloc(u64 n) {
    n = (n + 15) & ~((u64)15);
    if (g_arena_off + n > sizeof(g_arena)) return 0;
    void* p = &g_arena[g_arena_off];
    g_arena_off += n;
    return p;
}

// ── Math maison ──────────────────────────────────────────────────────────────
static double w_floor(double x){ long i=(long)x; if((double)i>x) i--; return (double)i; }
static double w_ceil (double x){ long i=(long)x; if((double)i<x) i++; return (double)i; }
static double w_fabs (double x){ return x<0.0?-x:x; }
static double w_sqrt (double x){ if(x<=0.0) return 0.0; double g=x; for(int k=0;k<30;k++){ if(g<=0.0) break; g=0.5*(g + x/g);} return g; }
static double w_fmod (double a,double b){ if(b==0.0) return 0.0; double q=(double)(long)(a/b); return a - q*b; }
static double w_pow  (double b,double e){ (void)b;(void)e; return 0.0; }   // SDF only (non utilisé)
static double w_cos  (double x){ (void)x; return 1.0; }                    // SDF only
static double w_acos (double x){ (void)x; return 0.0; }                    // SDF only
static void*  w_memcpy(void* d,const void* s,u64 n){ u8* dd=(u8*)d; const u8* ss=(const u8*)s; while(n--) *dd++=*ss++; return d; }
static void*  w_memset(void* d,int v,u64 n){ u8* dd=(u8*)d; while(n--) *dd++=(u8)v; return d; }

#define STBTT_ifloor(x)   ((int) w_floor(x))
#define STBTT_iceil(x)    ((int) w_ceil(x))
#define STBTT_sqrt(x)     w_sqrt(x)
#define STBTT_pow(x,y)    w_pow(x,y)
#define STBTT_fmod(x,y)   w_fmod(x,y)
#define STBTT_cos(x)      w_cos(x)
#define STBTT_acos(x)     w_acos(x)
#define STBTT_fabs(x)     w_fabs(x)
#define STBTT_malloc(x,u) ((void)(u), arena_alloc((u64)(x)))
#define STBTT_free(x,u)   ((void)(u),(void)(x))
#define STBTT_assert(x)   ((void)0)
#define STBTT_strlen(x)   0
#define STBTT_memcpy      w_memcpy
#define STBTT_memset      w_memset

#define STB_TRUETYPE_IMPLEMENTATION
#include "stb_truetype.h"

// ── État global du moteur de police ──────────────────────────────────────────
static stbtt_fontinfo g_font;
static int g_font_ok    = 0;
static int g_cur_glyph  = 0;
static u8  g_bmp[256*256];
static int g_bmp_w=0, g_bmp_h=0, g_bmp_xoff=0, g_bmp_yoff=0;

// ── Primitives exportées (noms exacts appelés par SluFontConf.slul) ──────────
int stb_font_init(const unsigned char* data) {
    if (!data) { g_font_ok = 0; return 0; }
    g_font_ok = stbtt_InitFont(&g_font, data, stbtt_GetFontOffsetForIndex(data, 0));
    return g_font_ok;
}
int stb_glyph_index(int codepoint) {
    if (!g_font_ok) return 0;
    return stbtt_FindGlyphIndex(&g_font, codepoint);
}
void stb_set_current_glyph(int gi) { g_cur_glyph = gi; }
int  stb_get_current_glyph(void)   { return g_cur_glyph; }

// Échelle * 1e6 (entier) pour hauteur em en pixels.
int stb_scale_k(int pixelSize) {
    if (!g_font_ok || pixelSize <= 0) return 0;
    float s = stbtt_ScaleForPixelHeight(&g_font, (float)pixelSize);
    return (int)(s * 1000000.0f);
}

// Rastérise le glyphe (index) à l'échelle donnée → bitmap alpha 8bpp dans g_bmp.
const unsigned char* stb_rasterize(int glyphIdx, int scaleK) {
    if (!g_font_ok || glyphIdx <= 0 || scaleK <= 0) return 0;
    g_arena_off = 0;                       // reset arène avant ce glyphe
    float scale = (float)scaleK / 1000000.0f;
    int w=0,h=0,xo=0,yo=0;
    unsigned char* bm = stbtt_GetGlyphBitmap(&g_font, scale, scale, glyphIdx, &w, &h, &xo, &yo);
    if (!bm || w <= 0 || h <= 0 || w > 256 || h > 256) { g_bmp_w=0; g_bmp_h=0; return 0; }
    for (int i = 0; i < w*h; i++) g_bmp[i] = bm[i];
    g_bmp_w = w; g_bmp_h = h; g_bmp_xoff = xo; g_bmp_yoff = yo;
    return g_bmp;
}
int stb_bmp_w(void)    { return g_bmp_w; }
int stb_bmp_h(void)    { return g_bmp_h; }
int stb_bmp_yoff(void) { return g_bmp_yoff; }
