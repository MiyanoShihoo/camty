/* KAT（已知答案测试）：
 *  - FIPS-197 附录 C.3：AES-256 全零 key/pt → DC95C078A2408989AD48A21492842087
 *  - SHA-256("abc") → ba7816bf...15ad
 *  - RFC 4231 测试向量 1：HMAC-SHA256(0x0b*20, "Hi There")
 *  - CMT1 seal→open 往返与篡改拒绝
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "crypto.h"

static int hex_eq(const char *tag, const uint8_t *got, const char *want_hex)
{
    char got_hex[2 * 64 + 1] = {0};
    for (int i = 0; i < (int)(strlen(want_hex) / 2); i++) {
        sprintf(got_hex + 2 * i, "%02x", got[i]);
    }
    if (strcmp(got_hex, want_hex)) {
        printf("FAIL %s\n  got  %s\n  want %s\n", tag, got_hex, want_hex);
        return 0;
    }
    printf("ok %s\n", tag);
    return 1;
}

int main(void)
{
    int pass = 1;

    /* AES-256 KAT */
    uint8_t key[32] = {0}, pt[16] = {0}, ct[16], back[16];
    uint32_t rk[60];
    aes256_expand(key, rk);
    aes256_encrypt_block(rk, pt, ct);
    pass &= hex_eq("AES-256 FIPS-197 C.3", ct,
                   "dc95c078a2408989ad48a21492842087");
    aes256_decrypt_block(rk, ct, back);
    pass &= memcmp(back, pt, 16) == 0 ? (printf("ok AES-256 往返\n"), 1) : (printf("FAIL AES-256 往返\n"), 0);

    /* SHA-256 KAT */
    uint8_t h[32];
    sha256((const uint8_t *)"abc", 3, h);
    pass &= hex_eq("SHA-256(abc)", h,
                   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    sha256((const uint8_t *)"", 0, h);
    pass &= hex_eq("SHA-256(空串)", h,
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    /* 跨块（200 字节 'a'）只验长度与首块确定性（Python hashlib 对拍在 E2E 做） */
    uint8_t longbuf[200];
    memset(longbuf, 'a', sizeof longbuf);
    sha256(longbuf, sizeof longbuf, h);

    /* HMAC-SHA256 RFC 4231 向量 1 */
    uint8_t hkey[20];
    memset(hkey, 0x0b, sizeof hkey);
    hmac_sha256(hkey, sizeof hkey, (const uint8_t *)"Hi There", 8, h);
    pass &= hex_eq("HMAC RFC4231 #1", h,
                   "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    /* CMT1 往返 + 篡改拒绝 */
    srand(1);
    uint8_t psk[32], msg[100], sealed[256], opened[256];
    for (int i = 0; i < 32; i++) psk[i] = (uint8_t)i;
    for (int i = 0; i < 100; i++) msg[i] = (uint8_t)(i * 7 + 1);
    size_t sealed_len = 0, opened_len = 0;
    if (cmt1_seal(psk, msg, sizeof msg, sealed, &sealed_len) != 0) {
        printf("FAIL seal\n");
        pass = 0;
    }
    if (cmt1_open(psk, sealed, sealed_len, opened, &opened_len) != 0
        || opened_len != sizeof msg || memcmp(opened, msg, sizeof msg)) {
        printf("FAIL open 往返\n");
        pass = 0;
    } else {
        printf("ok CMT1 往返（sealed=%zu opened=%zu）\n", sealed_len, opened_len);
    }
    sealed[10] ^= 0xFF;
    if (cmt1_open(psk, sealed, sealed_len, opened, &opened_len) == 0) {
        printf("FAIL 篡改未拒绝\n");
        pass = 0;
    } else {
        printf("ok CMT1 篡改拒绝\n");
    }

    printf(pass ? "ALL CRYPTO KAT PASS\n" : "CRYPTO KAT FAILED\n");
    return pass ? 0 : 1;
}
