
#include "chttp.h"
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#else
#include <openssl/evp.h>
#include <openssl/params.h>
#endif

#ifdef NDEBUG
#define UNREACHABLE
#else
#define UNREACHABLE __builtin_trap()
#endif

// If the URL is not being created correctly,
// uncomment this do dump the state of the
// builder at each step:
//
//   #define TRACE_BUILDER

// Error codes for the signature builder
#define SIG_OUT_OF_MEMORY -1
#define SIG_LIB_ERROR     -2

#ifndef PREALLOC_CAPACITY
#define PREALLOC_CAPACITY (1<<10)
#endif

//////////////////////////////////////////////////////////////////
// ENCODERS
//////////////////////////////////////////////////////////////////

static int hex_len(char *str, int len)
{
    (void) str;
    return 2 * len;
}

static int inplace_hex(char *buf, int len, bool up)
{
    int olen = hex_len(buf, len);
    if (olen == 0)
        return 0;

    int rlen = len;
    int wlen = olen;

    static const char uptable[] = "0123456789ABCDEF";
    static const char lotable[] = "0123456789abcdef";

    while (rlen > 0) {
        uint8_t b = (uint8_t) buf[--rlen];
        buf[--wlen] = (up ? uptable : lotable)[b & 0xF];
        buf[--wlen] = (up ? uptable : lotable)[b >> 4];
    }
    assert(rlen == 0);
    assert(wlen == 0);

    return 0;
}

static bool needs_percent(char c)
{
    if ((c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') ||
        (c == '-' || c == '_' || c == '.' || c == '~'))
        return false;
    return true;
}

static int pct_len(char *str, int len)
{
    int olen = 0;
    for (int i = 0; i < len; i++) {
        if (needs_percent(str[i]))
            olen += 3;
        else
            olen++;
    }
    return olen;
}

static int inplace_pct(char *buf, int len, bool up)
{
    int olen = pct_len(buf, len);
    if (olen == 0)
        return 0;

    int ridx = len;
    int widx = olen;

    static const char uptable[] = "0123456789ABCDEF";
    static const char lotable[] = "0123456789abcdef";

    while (ridx > 0) {
        char c = buf[--ridx];
        if (needs_percent(c)) {
            uint8_t b = c;
            buf[--widx] = (up ? uptable : lotable)[b & 0xF];
            buf[--widx] = (up ? uptable : lotable)[b >> 4];
            buf[--widx] = '%';
        } else {
            buf[--widx] = c;
        }
    }
    assert(ridx == 0);
    assert(widx == 0);

    return 0;
}

static int sha256_len(char *buf, int len)
{
    (void) buf;
    (void) len;
    return 32;
}

// src and dst may overlap
static int sha256(char *src, int len, char *dst)
{
#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status))
        return -1;

    BCRYPT_HASH_HANDLE hash = NULL;
    status = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return -1;
    }

    status = BCryptHashData(hash, (PUCHAR) src, (ULONG) len, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        return -1;
    }

    status = BCryptFinishHash(hash, (PUCHAR) dst, 32, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        return -1;
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return 0;
#else
    int olen = sha256_len(src, len);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_DigestUpdate(ctx, src, len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, (unsigned char*) dst, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    if (hash_len != (unsigned int) olen) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
#endif
    return 0;
}

static int inplace_sha256(char *buf, int len)
{
    return sha256(buf, len, buf);
}

static int hmac_len(char *buf, int len1, int len2)
{
    (void) buf;
    (void) len1;
    (void) len2;
    return 32;
}

static int inplace_hmac(char *buf, int len1, int len2)
{
    HTTP_String key = { buf, len1 };
    HTTP_String data = { buf + len1, len2 };

#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg,
        BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status))
        return -1;

    BCRYPT_HASH_HANDLE hash = NULL;
    status = BCryptCreateHash(alg, &hash, NULL, 0, (PUCHAR) key.ptr, (ULONG) key.len, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return -1;
    }

    status = BCryptHashData(hash, (PUCHAR) data.ptr, (ULONG) data.len, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        return -1;
    }

    status = BCryptFinishHash(hash, (PUCHAR) buf, 32, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        return -1;
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return 0;
#else
    int olen = hmac_len(buf, len1, len2);

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL) {
        return -1;
    }

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        return -1;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };

    if (EVP_MAC_init(ctx, (unsigned char*) key.ptr, key.len, params) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return -1;
    }

    if (EVP_MAC_update(ctx, (unsigned char*) data.ptr, data.len) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return -1;
    }

    size_t mac_len;
    if (EVP_MAC_final(ctx, (unsigned char*) buf, &mac_len, EVP_MAX_MD_SIZE) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return -1;
    }
    if (mac_len != (size_t) olen) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return -1;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return 0;
#endif
}

//////////////////////////////////////////////////////////////////
// BUILDER
//////////////////////////////////////////////////////////////////

#define MAX_MODIFIERS 32

typedef enum {
    MOD_HEX,
    MOD_PCT,
    MOD_SHA256,
    MOD_HMAC,
} ModifierType;

typedef struct {
    ModifierType type;
    int off_0;
    int off_1;
} Modifier;

typedef struct {
    char *dst;
    int   cap;
    int   len;
    Modifier mods[MAX_MODIFIERS];
    int num_mods;
    int status;
} Builder;

void builder_init(Builder *b, char *dst, int cap)
{
    b->dst = dst;
    b->cap = cap;
    b->len = 0;
    b->num_mods = 0;
    b->status = 0;
}

#ifdef TRACE_BUILDER
static void dump(Builder *builder, char *file, int line)
{
    printf("%s:%d\n", file, line);
    switch (builder->status) {
    case 0:
        printf("  status=OK\n");
        break;
    case SIG_OUT_OF_MEMORY:
        printf("  status=OUT_OF_MEMORY\n");
        break;
    case SIG_LIB_ERROR:
        printf("  status=LIB_ERROR\n");
        break;
    }
    printf("  len=%d\n", builder->len);
    printf("  dst=[\n    ");
    for (int i = 0; i < builder->len; i++) {
        if (i % 32 == 0)
            printf("\n    ");
        if (i < builder->cap) {
            char c = builder->dst[i];
            if ((uint8_t) c < 32 || (uint8_t) c > 127)
                putc('.', stdout);
            else
                putc(c, stdout);
        } else {
            putc('-', stdout);
        }
    }
    printf("\n  ]\n");
    printf("\n");
}
#endif

static void append_(Builder *b, HTTP_String s, char *file, int line)
{
    if (b->status == 0) {
        if (b->cap - b->len < s.len) {
            b->status = SIG_OUT_OF_MEMORY;
        } else {
            memcpy(b->dst + b->len, s.ptr, s.len);
        }
    }
    b->len += s.len;

#ifdef TRACE_BUILDER
    dump(b, file, line);
#else
    (void) file;
    (void) line;
#endif
}

static void push_mod(Builder *b, ModifierType m)
{
    assert(b->num_mods < MAX_MODIFIERS);

    b->mods[b->num_mods].type = m;
    b->mods[b->num_mods].off_0 = b->len;
    b->mods[b->num_mods].off_1 = -1;
    b->num_mods++;
}

static void flush(Builder *b)
{
    if (b->status != 0)
        return;

    assert(b->num_mods > 0);
    assert(b->mods[b->num_mods-1].type == MOD_HMAC);
    assert(b->mods[b->num_mods-1].off_1 == -1);

    b->mods[b->num_mods-1].off_1 = b->len;
}

static void pop_mod_(Builder *b, char *file, int line)
{
    assert(b->num_mods > 0);
    Modifier mod = b->mods[--b->num_mods];

    int olen;
    switch (mod.type) {
    case MOD_HEX:
        olen = hex_len(
            b->dst + mod.off_0,
            b->len - mod.off_0);
        break;
    case MOD_PCT:
        olen = pct_len(
            b->dst + mod.off_0,
            b->len - mod.off_0);
        break;
    case MOD_SHA256:
        olen = sha256_len(
            b->dst + mod.off_0,
            b->len - mod.off_0);
        break;
    case MOD_HMAC:
        olen = hmac_len(
            b->dst + mod.off_0,
            mod.off_1 - mod.off_0,
            b->len - mod.off_1);
        break;
    }

    if (olen > b->cap - mod.off_0
        && b->status == 0)
        b->status = SIG_OUT_OF_MEMORY;

    if (b->status == 0) {

        int ret;
        switch (mod.type) {
        case MOD_HEX:
            ret = inplace_hex(
                b->dst + mod.off_0,
                b->len - mod.off_0,
                false);
            break;
        case MOD_PCT:
            ret = inplace_pct(
                b->dst + mod.off_0,
                b->len - mod.off_0,
                true);
            break;
        case MOD_SHA256:
            ret = inplace_sha256(
                b->dst + mod.off_0,
                b->len - mod.off_0);
            break;
        case MOD_HMAC:
            ret = inplace_hmac(
                b->dst + mod.off_0,
                mod.off_1 - mod.off_0,
                b->len - mod.off_1);
            break;
        }

        if (ret < 0)
            b->status = SIG_LIB_ERROR;
    }

    b->len = mod.off_0 + olen;

#ifdef TRACE_BUILDER
    dump(b, file, line);
#else
    (void) file;
    (void) line;
#endif
}

#ifdef TRACE_BUILDER
#define append(b, s) append_(b, s, __FILE__, __LINE__)
#define pop_mod(b) pop_mod_(b, __FILE__, __LINE__)
#else
#define append(b, s) append_(b, s, NULL, 0)
#define pop_mod(b) pop_mod_(b, NULL, 0)
#endif

//////////////////////////////////////////////////////////////////
// SIGNING FUNCTION
//////////////////////////////////////////////////////////////////

// REQUEST AUTHENTICATION
//
// Requests are signed by clients using a secret shared with
// the server. The server only allows PUT and DELETE operations
// when a request is properly signed.
//
// The signing algorithm is HMAC-SHA256. Of course what is
// being signed is not the entire request string, but a canonical
// representation of it including only relevant information
// for its processing. The signature is then stored in the
// X-Blogtech-Signature header. To verify that a request is
// legitimate, a server recalculates the signature and checks
// whether the result matches the value of X-Blogtech-Signature.
//
// The canonical string must contain:
//   1. method
//   2. path
//   3. host
//   5. Date
//   6. expiration
//   7. nonce
//   8. content length
//   9. content hash

static HTTP_String method_to_str(HTTP_Method method)
{
    switch (method) {
    case HTTP_METHOD_GET    : return HTTP_STR("GET");
    case HTTP_METHOD_HEAD   : return HTTP_STR("HEAD");
    case HTTP_METHOD_POST   : return HTTP_STR("POST");
    case HTTP_METHOD_PUT    : return HTTP_STR("PUT");
    case HTTP_METHOD_DELETE : return HTTP_STR("DELETE");
    case HTTP_METHOD_CONNECT: return HTTP_STR("CONNECT");
    case HTTP_METHOD_OPTIONS: return HTTP_STR("OPTIONS");
    case HTTP_METHOD_TRACE  : return HTTP_STR("TRACE");
    case HTTP_METHOD_PATCH  : return HTTP_STR("PATCH");
    default:break;
    }
    return HTTP_STR("???");
}

int calculate_request_signature(
    HTTP_Method method,
    HTTP_String path,
    HTTP_String host,
    HTTP_String date,
    uint32_t    expire,
    HTTP_String nonce,
    HTTP_String body,
    HTTP_String secret,
    char *dst)
{
    char body_hash[32];
    if (sha256(body.ptr, body.len, body_hash) < 0)
        return -1;

    // Convert expire and body length to strings
    char expire_str[16];
    int expire_len = snprintf(expire_str, sizeof(expire_str), "%u", expire);
    if (expire_len < 0 || expire_len >= (int) sizeof(expire_str))
        return -1;

    char body_len_str[16];
    int body_len_len = snprintf(body_len_str, sizeof(body_len_str), "%d", body.len);
    if (body_len_len < 0 || body_len_len >= (int) sizeof(body_len_str))
        return -1;

    char pool[1<<12];
    Builder b;
    builder_init(&b, pool, sizeof(pool));
    push_mod(&b, MOD_HEX);
        push_mod(&b, MOD_HMAC);
            append(&b, secret);
            flush(&b);
            append(&b, method_to_str(method));
            append(&b, HTTP_STR("\n"));
            push_mod(&b, MOD_PCT);
                append(&b, path);
            pop_mod(&b);
            append(&b, HTTP_STR("\n"));
            append(&b, host);
            append(&b, HTTP_STR("\n"));
            append(&b, date);
            append(&b, HTTP_STR("\n"));
            append(&b, ((HTTP_String) { expire_str, expire_len }));
            append(&b, HTTP_STR("\n"));
            append(&b, nonce);
            append(&b, HTTP_STR("\n"));
            append(&b, ((HTTP_String) { body_len_str, body_len_len }));
            append(&b, HTTP_STR("\n"));
            push_mod(&b, MOD_HEX);
                append(&b, ((HTTP_String) { body_hash, sizeof(body_hash) }));
            pop_mod(&b);
        pop_mod(&b);
    pop_mod(&b);

    if (b.status != 0)
        return b.status;
    assert(b.len == 64);
    memcpy(dst, b.dst, 64);
    return 0;
}
