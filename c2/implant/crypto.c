/* CMT1 加密原语实现。
 * sbox/轮常量全部由算法推导（GF(2^8) 逆元 + 仿射变换 / xtime），
 * 不使用手抄查表；正确性由 build 时 KAT（FIPS-197 / SHA-256 "abc"）验证。
 */
#include "crypto.h"

#include <stdlib.h>
#include <string.h>
#include <windows.h>
#ifndef CMT1_NO_BCRYPT
#include <bcrypt.h>   /* MSVC 需要显式引入；mingw 的 windows.h 已含（头文件守卫幂等） */
#endif

/* RtlGenRandom：advapi32 导出（无公开头文件，手动声明） */
extern BOOLEAN WINAPI SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);

/* ---------- GF(2^8) ---------- */

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    while (b) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static uint8_t gf_inv(uint8_t a)
{
    /* GF(2^8) 上穷举逆元（初始化路径，非热点） */
    for (int b = 1; b < 256; b++) {
        if (gf_mul(a, (uint8_t)b) == 1) return (uint8_t)b;
    }
    return 0;
}

static uint8_t rotl8(uint8_t v, int n)
{
    return (uint8_t)((v << n) | (v >> (8 - n)));
}

static uint8_t SBOX[256];
static uint8_t RSBOX[256];
static int tables_ready = 0;

static void init_tables(void)
{
    if (tables_ready) return;
    for (int i = 0; i < 256; i++) {
        uint8_t inv = gf_inv((uint8_t)i);
        uint8_t s = (uint8_t)(inv ^ rotl8(inv, 1) ^ rotl8(inv, 2)
                              ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63);
        SBOX[i] = s;
        RSBOX[s] = (uint8_t)i;
    }
    tables_ready = 1;
}

/* ---------- AES-256 ---------- */

void aes256_expand(const uint8_t key[32], uint32_t rk[60])
{
    init_tables();
    for (int i = 0; i < 8; i++) {
        rk[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16)
                | ((uint32_t)key[4 * i + 2] << 8) | key[4 * i + 3];
    }
    uint8_t rcon = 1;
    for (int i = 8; i < 60; i++) {
        uint32_t t = rk[i - 1];
        if (i % 8 == 0) {
            t = (t << 8) | (t >> 24);                          /* RotWord */
            t = ((uint32_t)SBOX[(t >> 24) & 0xff] << 24)
                | ((uint32_t)SBOX[(t >> 16) & 0xff] << 16)
                | ((uint32_t)SBOX[(t >> 8) & 0xff] << 8)
                | (uint32_t)SBOX[t & 0xff];                    /* SubWord */
            t ^= ((uint32_t)rcon << 24);
            rcon = gf_mul(rcon, 2);                            /* xtime */
        } else if (i % 8 == 4) {
            t = ((uint32_t)SBOX[(t >> 24) & 0xff] << 24)
                | ((uint32_t)SBOX[(t >> 16) & 0xff] << 16)
                | ((uint32_t)SBOX[(t >> 8) & 0xff] << 8)
                | (uint32_t)SBOX[t & 0xff];
        }
        rk[i] = rk[i - 8] ^ t;
    }
}

static void add_round_key(uint8_t st[16], const uint32_t rk[60], int round)
{
    for (int c = 0; c < 4; c++) {
        uint32_t w = rk[round * 4 + c];
        st[c * 4 + 0] ^= (uint8_t)(w >> 24);
        st[c * 4 + 1] ^= (uint8_t)(w >> 16);
        st[c * 4 + 2] ^= (uint8_t)(w >> 8);
        st[c * 4 + 3] ^= (uint8_t)w;
    }
}

void aes256_encrypt_block(const uint32_t rk[60], const uint8_t in[16], uint8_t out[16])
{
    uint8_t st[16];
    memcpy(st, in, 16);
    add_round_key(st, rk, 0);
    for (int round = 1; round <= 13; round++) {
        for (int i = 0; i < 16; i++) st[i] = SBOX[st[i]];
        /* ShiftRows：行 r 左移 r */
        uint8_t t;
        t = st[1]; st[1] = st[5]; st[5] = st[9]; st[9] = st[13]; st[13] = t;
        t = st[2]; st[2] = st[10]; st[10] = t;
        t = st[6]; st[6] = st[14]; st[14] = t;
        t = st[15]; st[15] = st[11]; st[11] = st[7]; st[7] = st[3]; st[3] = t;
        /* MixColumns */
        for (int c = 0; c < 4; c++) {
            uint8_t *p = st + c * 4;
            uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
            p[0] = (uint8_t)(gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3);
            p[1] = (uint8_t)(a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3);
            p[2] = (uint8_t)(a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3));
            p[3] = (uint8_t)(gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2));
        }
        add_round_key(st, rk, round);
    }
    for (int i = 0; i < 16; i++) st[i] = SBOX[st[i]];
    uint8_t t;
    t = st[1]; st[1] = st[5]; st[5] = st[9]; st[9] = st[13]; st[13] = t;
    t = st[2]; st[2] = st[10]; st[10] = t;
    t = st[6]; st[6] = st[14]; st[14] = t;
    t = st[15]; st[15] = st[11]; st[11] = st[7]; st[7] = st[3]; st[3] = t;
    add_round_key(st, rk, 14);
    memcpy(out, st, 16);
}

void aes256_decrypt_block(const uint32_t rk[60], const uint8_t in[16], uint8_t out[16])
{
    uint8_t st[16];
    memcpy(st, in, 16);
    add_round_key(st, rk, 14);
    uint8_t t;
    for (int round = 13; round >= 1; round--) {
        /* InvShiftRows：行 r 右移 r */
        t = st[13]; st[13] = st[9]; st[9] = st[5]; st[5] = st[1]; st[1] = t;
        t = st[10]; st[10] = st[2]; st[2] = t;
        t = st[14]; st[14] = st[6]; st[6] = t;
        t = st[3]; st[3] = st[7]; st[7] = st[11]; st[11] = st[15]; st[15] = t;
        for (int i = 0; i < 16; i++) st[i] = RSBOX[st[i]];
        add_round_key(st, rk, round);
        /* InvMixColumns（0e 0b 0d 09） */
        for (int c = 0; c < 4; c++) {
            uint8_t *p = st + c * 4;
            uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
            p[0] = (uint8_t)(gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9));
            p[1] = (uint8_t)(gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13));
            p[2] = (uint8_t)(gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11));
            p[3] = (uint8_t)(gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14));
        }
    }
    t = st[13]; st[13] = st[9]; st[9] = st[5]; st[5] = st[1]; st[1] = t;
    t = st[10]; st[10] = st[2]; st[2] = t;
    t = st[14]; st[14] = st[6]; st[6] = t;
    t = st[3]; st[3] = st[7]; st[7] = st[11]; st[11] = st[15]; st[15] = t;
    for (int i = 0; i < 16; i++) st[i] = RSBOX[st[i]];
    add_round_key(st, rk, 0);
    memcpy(out, st, 16);
}

/* ---------- CBC + PKCS7 ---------- */

int cmt1_cbc_encrypt(const uint8_t *key, const uint8_t *iv,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len)
{
    uint32_t rk[60];
    aes256_expand(key, rk);
    uint8_t pad = (uint8_t)(16 - in_len % 16); /* 1..16，整块时补 16 */
    size_t padded = in_len + pad;
    const uint8_t *prev = iv;
    for (size_t off = 0; off < padded; off += 16) {
        uint8_t block[16];
        for (size_t i = 0; i < 16; i++) {
            uint8_t b = (off + i < in_len) ? in[off + i] : pad;
            block[i] = (uint8_t)(b ^ prev[i]);
        }
        aes256_encrypt_block(rk, block, out + off);
        prev = out + off;
    }
    *out_len = padded;
    return 0;
}

int cmt1_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len)
{
    if (in_len == 0 || in_len % 16) return -1;
    uint32_t rk[60];
    aes256_expand(key, rk);
    uint8_t block[16];
    for (size_t off = 0; off < in_len; off += 16) {
        aes256_decrypt_block(rk, in + off, block);
        for (int i = 0; i < 16; i++) out[off + i] = block[i] ^ (off ? in[off - 16 + i] : iv[i]);
    }
    uint8_t pad = out[in_len - 1];
    if (pad < 1 || pad > 16) return -1;
    for (int i = 0; i < pad; i++) {
        if (out[in_len - 1 - i] != pad) return -1;
    }
    *out_len = in_len - pad;
    return 0;
}

/* ---------- SHA-256 ---------- */

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t ror32(uint32_t v, int n) { return (v >> n) | (v << (32 - n)); }

void sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    size_t padded_len = ((len + 8) / 64 + 1) * 64;
    uint64_t bits = (uint64_t)len * 8;
    for (size_t base = 0; base < padded_len; base += 64) {
        uint8_t blk[64];
        size_t remain = (base < len) ? len - base : 0;
        memset(blk, 0, 64);
        if (remain > 0) {
            size_t n = remain < 64 ? remain : 64;
            memcpy(blk, data + base, n);
            if (n < 64) blk[n] = 0x80;
        } else {
            blk[0] = 0x80;
        }
        if (base + 64 == padded_len) { /* 尾块写长度 */
            for (int i = 0; i < 8; i++) {
                blk[63 - i] = (uint8_t)(bits >> (8 * i));
            }
        }
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)blk[i * 4] << 24) | ((uint32_t)blk[i * 4 + 1] << 16)
                   | ((uint32_t)blk[i * 4 + 2] << 8) | blk[i * 4 + 3];
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + SHA256_K[i] + w[i];
            uint32_t S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    for (int i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)h[i];
    }
}

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    uint8_t k[64], ipad[64], opad[64], inner[64 + 32];
    memset(k, 0, 64);
    if (key_len > 64) {
        sha256(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    memcpy(inner, ipad, 64);
    /* 分段喂给 sha256：64+msg_len 字节流 → 用缓冲拼接（本协议数据 ≤ 数 KB，栈/堆一次拼） */
    uint8_t *buf = (uint8_t *)malloc(64 + msg_len);
    memcpy(buf, ipad, 64);
    memcpy(buf + 64, msg, msg_len);
    uint8_t ih[32];
    sha256(buf, 64 + msg_len, ih);
    free(buf);
    uint8_t ob[64 + 32];
    memcpy(ob, opad, 64);
    memcpy(ob + 64, ih, 32);
    sha256(ob, 64 + 32, out);
}

/* ---------- CMT1 ---------- */

/* CSPRNG：优先 BCryptGenRandom（bcrypt.lib，系统首选 RNG）；运行失败或构建链
 * 不支持（-DCMT1_NO_BCRYPT）时退 SystemFunction036（RtlGenRandom，advapi32）。
 * 两种来源均为操作系统 CSPRNG。返回 0 成功；都失败返回 -1（fail-closed）。 */
int cmt1_random_bytes(uint8_t *buf, size_t n)
{
    if (buf == NULL || n == 0) return -1;
#ifndef CMT1_NO_BCRYPT
    if (BCryptGenRandom((BCRYPT_ALG_HANDLE)0, (PUCHAR)buf, (ULONG)n,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0)
        return 0;
#endif
    if (SystemFunction036(buf, (ULONG)n)) return 0;
    return -1;
}

/* IV 来自 cmt1_random_bytes（BCryptGenRandom/RtlGenRandom）。
 * 协议字节格式不变（magic|iv|ct|mac，IV 16 字节），仅随机源更换。 */

int cmt1_seal(const uint8_t psk[CMT1_KEY_LEN],
              const uint8_t *plaintext, size_t pt_len,
              uint8_t *out, size_t *out_len)
{
    static const uint8_t magic[4] = {'C', 'M', 'T', '1'};
    memcpy(out, magic, 4);
    uint8_t *iv = out + 4;
    if (cmt1_random_bytes(iv, CMT1_IV_LEN) != 0) return -1;
    uint8_t *ct = out + 4 + CMT1_IV_LEN;
    size_t ct_len = 0;
    if (cmt1_cbc_encrypt(psk, iv, plaintext, pt_len, ct, &ct_len) != 0) return -1;
    uint8_t mac[CMT1_MAC_LEN];
    uint8_t *mac_input = (uint8_t *)malloc(4 + CMT1_IV_LEN + ct_len);
    memcpy(mac_input, out, 4 + CMT1_IV_LEN);
    memcpy(mac_input + 4 + CMT1_IV_LEN, ct, ct_len);
    hmac_sha256(psk, CMT1_KEY_LEN, mac_input, 4 + CMT1_IV_LEN + ct_len, mac);
    free(mac_input);
    memcpy(out + 4 + CMT1_IV_LEN + ct_len, mac, CMT1_MAC_LEN);
    *out_len = 4 + CMT1_IV_LEN + ct_len + CMT1_MAC_LEN;
    return 0;
}

int cmt1_open(const uint8_t psk[CMT1_KEY_LEN],
              const uint8_t *blob, size_t blob_len,
              uint8_t *out, size_t *out_len)
{
    static const uint8_t magic[4] = {'C', 'M', 'T', '1'};
    if (blob_len < 4 + CMT1_IV_LEN + 16 + CMT1_MAC_LEN) return -1;
    if (memcmp(blob, magic, 4) != 0) return -1;
    const uint8_t *iv = blob + 4;
    size_t ct_len = blob_len - 4 - CMT1_IV_LEN - CMT1_MAC_LEN;
    const uint8_t *ct = blob + 4 + CMT1_IV_LEN;
    const uint8_t *mac = blob + 4 + CMT1_IV_LEN + ct_len;
    uint8_t expect[CMT1_MAC_LEN];
    hmac_sha256(psk, CMT1_KEY_LEN, blob, 4 + CMT1_IV_LEN + ct_len, expect);
    /* 恒时比较 */
    uint8_t diff = 0;
    for (int i = 0; i < CMT1_MAC_LEN; i++) diff |= expect[i] ^ mac[i];
    if (diff) return -1;
    return cmt1_cbc_decrypt(psk, iv, ct, ct_len, out, out_len);
}
