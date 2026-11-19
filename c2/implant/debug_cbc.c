#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "crypto.h"

int main(void) {
    srand(1);
    uint8_t psk[32], msg[100], sealed[256], opened[256];
    for (int i = 0; i < 32; i++) psk[i] = (uint8_t)i;
    for (int i = 0; i < 100; i++) msg[i] = (uint8_t)(i * 7 + 1);
    size_t sealed_len = 0, opened_len = 0;

    if (cmt1_seal(psk, msg, sizeof msg, sealed, &sealed_len) != 0) { printf("seal fail\n"); return 1; }
    printf("sealed_len=%zu (expect 4+16+112+32=164)\n", sealed_len);

    /* 单独测 CBC 加解密（不经 MAC 层） */
    uint8_t iv[16], ct[128], back[128];
    for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(i + 100);
    size_t ct_len = 0, back_len = 0;
    cmt1_cbc_encrypt(psk, iv, msg, 100, ct, &ct_len);
    printf("ct_len=%zu\n", ct_len);
    int rc = cmt1_cbc_decrypt(psk, iv, ct, ct_len, back, &back_len);
    printf("cbc decrypt rc=%d back_len=%zu\n", rc, back_len);
    if (back_len == 100) printf("cbc content match: %d\n", memcmp(back, msg, 100) == 0);

    int o_rc = cmt1_open(psk, sealed, sealed_len, opened, &opened_len);
    printf("open rc=%d opened_len=%zu\n", o_rc, opened_len);
    if (o_rc == 0) {
        for (int i = 0; i < 100; i++) {
            if (opened[i] != msg[i]) { printf("first diff at %d: got %02x want %02x\n", i, opened[i], msg[i]); break; }
        }
    }
    return 0;
}
