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
    if (!pad) {
        int rem = len % 3;
        if (0) {}
        else if (rem == 2) olen -= 1;
        else if (rem == 1) olen -= 2;
    }
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
    case ENCODING_HEX:
    case ENCODING_HEXL:
        return hex_len(buf, len1);
    case ENCODING_PCT:
    case ENCODING_PCTL:
        return pct_len(buf, len1);
    case ENCODING_B64:
        return b64_len(buf, len1, true, false);
    case ENCODING_B64NP:
        return b64_len(buf, len1, false, false);
    case ENCODING_B64URL:
        return b64_len(buf, len1, true, true);
    case ENCODING_B64URLNP:
        return b64_len(buf, len1, false, true);
    }
    return -1;
}

int encode_inplace(char *buf, int len1, int len2, int cap, Encoding enc)
{
    if (enc != ENCODING_HMAC && len2 > 0)
        return -1;

    int olen = encode_len(buf, len1, len2, enc);
    if (olen < 0 || olen > cap)
        return olen;

    int ret;
    switch (enc) {
    case ENCODING_SHA256:
        ret = inplace_sha256(buf, len1);
        break;
    case ENCODING_HMAC:
        ret = inplace_hmac(buf, len1, len2);
        break;
    case ENCODING_HEX:
        ret = inplace_hex(buf, len1, true);
        break;
    case ENCODING_HEXL:
        ret = inplace_hex(buf, len1, false);
        break;
    case ENCODING_PCT:
        ret = inplace_pct(buf, len1, true);
        break;
    case ENCODING_PCTL:
        ret = inplace_pct(buf, len1, false);
        break;
    case ENCODING_B64:
        ret = inplace_b64(buf, len1, true, false);
        break;
    case ENCODING_B64NP:
        ret = inplace_b64(buf, len1, false, false);
        break;
    case ENCODING_B64URL:
        ret = inplace_b64(buf, len1, true, true);
        break;
    case ENCODING_B64URLNP:
        ret = inplace_b64(buf, len1, false, true);
        break;
    }
    if (ret < 0)
        return ret;

    return olen;
}

static int hex_char_to_int(char c)
{
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= '0' && c <= '9') return c - '0';
    return -1;
}

static int decode_hex_len(char *buf, int len)
{
    (void) buf;
    return (len >> 1) + (len & 1);
}

static int inplace_decode_hex(char *buf, int len)
{
    int odd = len & 1;
    len -= odd;

    for (int i = 0; i < len; i += 2) {
        int a = hex_char_to_int(buf[i+0]);
        int b = hex_char_to_int(buf[i+1]);
        if (a < 0 || b < 0) return -1;
        buf[i >> 1] = (char) ((a << 4) | b);
    }

    if (odd) {
        int a = hex_char_to_int(buf[len]);
        if (a < 0) return -1;
        buf[len >> 1] = (char) (a << 4); // TODO: is this right? Should it be shifted by 0?
    }

    return 0;
}

static int decode_pct_len(char *buf, int len)
{
    int olen = 0;
    for (int i = 0; i < len; i++) {
        if (buf[i] == '%')
            i += 2;
        olen++;
    }
    return olen;
}

static int inplace_decode_pct(char *buf, int len)
{
    int rd = 0;
    int wr = 0;
    while (rd < len) {
        char c;
        if (buf[rd] == '%') {
            if (len - rd <= 2)
                return -1;
            int a = hex_char_to_int(buf[rd+1]);
            int b = hex_char_to_int(buf[rd+2]);
            if (a < 0 || b < 0)
                return -1;
            c = (char) ((a << 4) | b);
            rd += 3;
        } else {
            c = buf[rd];
            rd++;
        }

        buf[wr] = c;
        wr++;
    }
    return 0;
}

static int remove_padding(char *buf, int len)
{
    while (len > 0 && buf[len-1] == '=')
        len--;
    return len;
}

static int decode_b64_len(char *buf, int len)
{
    len = remove_padding(buf, len);
    int rem = len % 4;
    int olen = len / 4 * 3;
    if (0) {}
    else if (rem == 2) olen += 1;
    else if (rem == 3) olen += 2;
    return olen;
}

static int b64_char_to_int(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+') return 62;
    if (c == '_' || c == '/') return 63;
    return -1;
}

static int inplace_decode_b64(char *buf, int len)
{
    len = remove_padding(buf, len);

    int rem = len % 4;
    len -= rem;

    int ridx = 0;
    int widx = 0;

    while (ridx < len) {

        int a = b64_char_to_int(buf[ridx+0]);
        int b = b64_char_to_int(buf[ridx+1]);
        int c = b64_char_to_int(buf[ridx+2]);
        int d = b64_char_to_int(buf[ridx+3]);

        if (a < 0 || b < 0 ||
            c < 0 || d < 0)
            return -1;

        buf[widx+0] = (char) ((a << 2) | (b >> 4));
        buf[widx+1] = (char) ((b << 4) | (c >> 2));
        buf[widx+2] = (char) ((c << 6) | (d >> 0));

        ridx += 4;
        widx += 3;
    }

    switch (rem) {
        int a;
        int b;
        int c;
    case 1:
        return -1;
    case 2:
        a = b64_char_to_int(buf[len+0]);
        b = b64_char_to_int(buf[len+1]);
        if (a < 0 || b < 0)
            return -1;
        buf[widx+0] = (char) ((a << 2) | (b >> 4));
        widx += 1;
        break;
    case 3:
        a = b64_char_to_int(buf[len+0]);
        b = b64_char_to_int(buf[len+1]);
        c = b64_char_to_int(buf[len+2]);
        if (a < 0 || b < 0 || c < 0)
            return -1;
        buf[widx+0] = (char) ((a << 2) | (b >> 4));
        buf[widx+1] = (char) ((b << 4) | (c >> 2));
        widx += 2;
        break;
    }

    return 0;
}

int decode_len(char *buf, int len, Encoding enc)
{
    switch (enc) {
    case ENCODING_HEX:
        return decode_hex_len(buf, len);
    case ENCODING_PCT:
        return decode_pct_len(buf, len);
    case ENCODING_B64:
        return decode_b64_len(buf, len);
    }
    return -1;
}

int decode_inplace(char *buf, int len, int cap, Encoding enc)
{
    int olen = decode_len(buf, len, enc);
    if (olen < 0 || olen > len)
        return olen;

    int ret;
    switch (enc) {
    case ENCODING_HEX:
        ret = inplace_decode_hex(buf, len);
        break;
    case ENCODING_PCT:
        ret = inplace_decode_pct(buf, len);
        break;
    case ENCODING_B64:
        ret = inplace_decode_b64(buf, len);
        break;
    }
    if (ret < 0)
        return ret;

    return olen;
}
