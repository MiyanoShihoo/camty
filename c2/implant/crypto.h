/* CMT1 协议加密原语：AES-256-CBC + SHA-256 + HMAC-SHA256（零外部依赖）。
 * 与 c2/server/protocol.py 互操作，一致性由 KAT 与 E2E 保证。
 */
#ifndef CAMTY_C2_CRYPTO_H
#define CAMTY_C2_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define CMT1_KEY_LEN 32
#define CMT1_IV_LEN 16
#define CMT1_MAC_LEN 32

/* AES-256（rk 为 60 个 32 位轮密钥字） */
void aes256_expand(const uint8_t key[32], uint32_t rk[60]);
void aes256_encrypt_block(const uint32_t rk[60], const uint8_t in[16], uint8_t out[16]);
void aes256_decrypt_block(const uint32_t rk[60], const uint8_t in[16], uint8_t out[16]);

/* CBC + PKCS7。成功返回 0，out_len 为输出长度；解密填充非法返回 -1。 */
int cmt1_cbc_encrypt(const uint8_t *key, const uint8_t *iv,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len);
int cmt1_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len);

/* SHA-256 / HMAC-SHA256 */
void sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len, uint8_t out[32]);

/* CMT1 封装：magic|iv|ct|mac。out 容量需 in_len + 4 + 16 + 32。成功返回 0。 */
int cmt1_seal(const uint8_t psk[CMT1_KEY_LEN],
              const uint8_t *plaintext, size_t pt_len,
              uint8_t *out, size_t *out_len);
/* 校验 MAC 并解密。失败返回 -1（PSK 不匹配或被篡改）。 */
int cmt1_open(const uint8_t psk[CMT1_KEY_LEN],
              const uint8_t *blob, size_t blob_len,
              uint8_t *out, size_t *out_len);

#endif
