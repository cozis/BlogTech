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

#include "basic.h"
#include "encode.h"

static int hex_len(char *str, int len)
{
    (void) str;
    return 2 * len;
}

static int inplace_hex(char *buf, int len, b8 up)
{
    int olen = hex_len(buf, len);
    if (olen == 0)
        return 0;

    int rlen = len;
    int wlen = olen;

    static const char uptable[] = "0123456789ABCDEF";
    static const char lotable[] = "0123456789abcdef";

    while (rlen > 0) {
        u8 b = (u8) buf[--rlen];
        buf[--wlen] = (up ? uptable : lotable)[b & 0xF];
        buf[--wlen] = (up ? uptable : lotable)[b >> 4];
    }
    ASSERT(rlen == 0);
    ASSERT(wlen == 0);

    return 0;
}

static b8 needs_percent(char c)
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

static int inplace_pct(char *buf, int len, b8 up)
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
            u8 b = c;
            buf[--widx] = (up ? uptable : lotable)[b & 0xF];
            buf[--widx] = (up ? uptable : lotable)[b >> 4];
            buf[--widx] = '%';
        } else {
            buf[--widx] = c;
        }
    }
    ASSERT(ridx == 0);
    ASSERT(widx == 0);

    return 0;
}

static int sha256_len(char *buf, int len)
{
    (void) buf;
    (void) len;
    return 32;
}

// src and dst may overlap
int sha256(char *src, int len, char *dst)
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
    string key = { buf, len1 };
    string data = { buf + len1, len2 };

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

static int b64_len(char *str, int len, b8 pad, b8 url)
{
    (void) str;
    (void) url;
    int olen = (len + 2) / 3 * 4;
    int rem = len % 3;
    if (0) {}
    else if (rem == 2) olen -= 1;
    else if (rem == 1) olen -= 2;
    return olen;
}

static int inplace_b64(char *buf, int len, b8 pad, b8 url)
{
    u8 *ptr = (u8*) buf;

    int olen = b64_len((char*) ptr, len, pad, url);
    if (olen == 0)
        return 0;
    ASSERT(len > 0);

    // Since the conversion happens in-place, we need to translate
    // left to right to avoid overwriting the input with the output
    int ridx = len; // Read index
    int widx = olen; // Write index

    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_";

    // First we handle the input bytes that don't form a full group
    int rem = len % 3;
    if (rem == 2) {
        uint8_t b = ptr[--ridx];
        uint8_t a = ptr[--ridx];
        ptr[--widx] = '=';
        ptr[--widx] = table[(b << 2) & 0x3F];
        ptr[--widx] = table[((a << 4) | (b >> 4)) & 0x3F];
        ptr[--widx] = table[a >> 2];
    } else if (rem == 1) {
        uint8_t a = ptr[--ridx];
        ptr[--widx] = '=';
        ptr[--widx] = '=';
        ptr[--widx] = table[(a << 4) & 0x3F];
        ptr[--widx] = table[a >> 2];
    }

    while (ridx > 0) {
        ridx -= 3;
        widx -= 4;
        uint8_t a = ptr[ridx+0] >> 2;
        uint8_t b = ((ptr[ridx+0] << 4) | (ptr[ridx+1] >> 4)) & 0x3F;
        uint8_t c = ((ptr[ridx+1] << 2) | (ptr[ridx+2] >> 6)) & 0x3F;
        uint8_t d = ptr[ridx+2] & 0x3F;
        ptr[widx+0] = table[a];
        ptr[widx+1] = table[b];
        ptr[widx+2] = table[c];
        ptr[widx+3] = table[d];
    }

    if (!pad) {
        while (olen > 0 && ptr[olen-1] == '=')
            olen--;
    }

    if (!url) {
        for (int i = 0; i < olen; i++) {
            if (0) {}
            else if (ptr[i] == '-') ptr[i] = '+';
            else if (ptr[i] == '_') ptr[i] = '/';
        }
    }

    return olen;
}

int encode_len(char *buf, int len1, int len2, Encoding enc)
{
    if (enc != ENCODING_HMAC && len2 > 0)
        return -1;
    switch (enc) {
    case ENCODING_SHA256:
        return sha256_len(buf, len1);
    case ENCODING_HMAC:
        return hmac_len(buf, len1, len2);
    case ENCODING_HEXU:
    case ENCODING_HEXL:
        return hex_len(buf, len1);
    case ENCODING_PCTU:
    case ENCODING_PCTL:
        return pct_len(buf, len1);
    case ENCODING_B64P:
        return b64_len(buf, len1, true, false);
    case ENCODING_B64NP:
        return b64_len(buf, len1, false, false);
    case ENCODING_B64URLP:
        return b64_len(buf, len1, true, true);
    case ENCODING_B64URLNP:
        return b64_len(buf, len1, false, true);
    }
    return -1;
}

int encode_inplace(char *buf, int len1, int len2, int cap, Encoding enc)
{
    int olen = encode_len(buf, len1, len2, enc);
    if (olen < 0)
        return -1;
    if (enc != ENCODING_HMAC && len2 > 0)
        return -1;
    if (cap < olen)
        return -1;
    switch (enc) {
    case ENCODING_SHA256:
        return inplace_sha256(buf, len1);
    case ENCODING_HMAC:
        return inplace_hmac(buf, len1, len2);
    case ENCODING_HEXU:
        return inplace_hex(buf, len1, true);
    case ENCODING_HEXL:
        return inplace_hex(buf, len1, false);
    case ENCODING_PCTU:
        return inplace_pct(buf, len1, true);
    case ENCODING_PCTL:
        return inplace_pct(buf, len1, false);
    case ENCODING_B64P:
        return inplace_b64(buf, len1, true, false);
    case ENCODING_B64NP:
        return inplace_b64(buf, len1, false, false);
    case ENCODING_B64URLP:
        return inplace_b64(buf, len1, true, true);
    case ENCODING_B64URLNP:
        return inplace_b64(buf, len1, false, true);
    }
    return -1;
}
