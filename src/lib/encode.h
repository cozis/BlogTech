#ifndef ENCODE_INCLUDED
#define ENCODE_INCLUDED

typedef enum {
    ENCODING_SHA256,
    ENCODING_HMAC,
    ENCODING_HEXU,
    ENCODING_HEXL,
    ENCODING_PCTU,
    ENCODING_PCTL,
    ENCODING_B64PU,
    ENCODING_B64PL,
    ENCODING_B64URLPU,
    ENCODING_B64URLPL,
    ENCODING_B64NPU,
    ENCODING_B64NPL,
    ENCODING_B64URLNPU,
    ENCODING_B64URLNPL,
} Encoding;

int encode_len(char *buf, int len1, int len2, Encoding enc);
int encode_inplace(char *buf, int len1, int len2, int cap, Encoding enc);

// SHA256 hash function
int sha256(char *src, int len, char *dst);

#endif // ENCODE_INCLUDED
