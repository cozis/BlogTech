#ifndef ENCODE_INCLUDED
#define ENCODE_INCLUDED

// Number of bytes required to encode
// N bytes as base64url
#define BASE64URL_LEN(N) (CEIL(N, 3) * 4)

typedef enum {

    // Raw SHA256 hash
    ENCODING_SHA256,

    // Raw HMAC (using SHA256)
    ENCODING_HMAC,

    // Hex string with uppercase letters
    ENCODING_HEXU,

    // Hex string with lowercase letters
    ENCODING_HEXL,

    // Percent-encoding with uppercase letters
    ENCODING_PCTU,

    // Percent-encoding with lowercase letters
    ENCODING_PCTL,

    // Base64-encoding with padding
    ENCODING_B64P,

    // Base64-encoding without padding
    ENCODING_B64NP,

    // Base64URL-encoding with padding
    ENCODING_B64URLP,

    // Base64URL-encoding without padding
    ENCODING_B64URLNP,
} Encoding;

int encode_len(char *buf, int len1, int len2, Encoding enc);
int encode_inplace(char *buf, int len1, int len2, int cap, Encoding enc);

// SHA256 hash function
int sha256(char *src, int len, char *dst);

#endif // ENCODE_INCLUDED
