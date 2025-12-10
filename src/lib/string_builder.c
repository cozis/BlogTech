#include "string_builder.h"

void sb_init(StringBuilder *b, char *dst, int cap)
{
    b->dst = dst;
    b->cap = cap;
    b->len = 0;
    b->num_mods = 0;
    b->status = 0;
}

#define WRITE_INTEGER(N, S)         \
    char dst[(N)+1];                \
    b8 neg = false;                 \
    if (S) {                        \
        if (v < 0) {                \
            neg = true;             \
            v = -v;                 \
        }                           \
    }                               \
    int magn = 1;                   \
    for (int i = 0; i < (N)-1; i++) \
        magn *= 10;                 \
    dst[0] = '0';                   \
    for (int i = 0; i < (N); i++) { \
        int d = v / magn;           \
        ASSERT(d >= 0 && d <= 9);   \
        dst[i+1] = '0'+ d;          \
        v %= magn;                  \
        magn /= 10;                 \
    }                               \
    int skip = 1;                   \
    while (skip < (N)+1 && dst[skip] == '0') \
        skip++;                    \
    if (skip == (N)+1)             \
        skip--;                    \
    if (neg) dst[--skip] = '-';    \
    sb_write_str(b, (string) { dst + skip, (N) + 1 - skip });

void sb_write_u8(StringBuilder *b, u8 v)
{
    WRITE_INTEGER(3, 0)
}

void sb_write_u16(StringBuilder *b, u16 v)
{
    WRITE_INTEGER(5, 0)
}

void sb_write_u32(StringBuilder *b, u32 v)
{
    WRITE_INTEGER(10, 0)
}

void sb_write_u64(StringBuilder *b, u64 v)
{
    WRITE_INTEGER(20, 0)
}

void sb_write_s8(StringBuilder *b, s8 v)
{
    WRITE_INTEGER(3, 1)
}

void sb_write_s16(StringBuilder *b, s16 v)
{
    WRITE_INTEGER(5, 1)
}

void sb_write_s32(StringBuilder *b, s32 v)
{
    WRITE_INTEGER(10, 1)
}

void sb_write_s64(StringBuilder *b, s64 v)
{
    WRITE_INTEGER(19, 1)
}

void sb_write_b8(StringBuilder *b, b8 v)
{
    sb_write_str(b, v ? S("true") : S("false"));
}

void sb_write_str(StringBuilder *b, string s)
{
    if (b->status == 0) {
        if (b->cap - b->len < s.len) {
            b->status = SB_OUT_OF_MEMORY;
        } else {
            memcpy_(b->dst + b->len, s.ptr, s.len);
        }
    }
    b->len += s.len;
}

void sb_write_arg(StringBuilder *b, Arg arg)
{
    switch (arg.type) {
    case ARG_TYPE_U8:
        sb_write_u8(b, arg.value_u8);
        break;
    case ARG_TYPE_U16:
        sb_write_u16(b, arg.value_u16);
        break;
    case ARG_TYPE_U32:
        sb_write_u32(b, arg.value_u32);
        break;
    case ARG_TYPE_U64:
        sb_write_u64(b, arg.value_u64);
        break;
    case ARG_TYPE_S8:
        sb_write_s8(b, arg.value_s8);
        break;
    case ARG_TYPE_S16:
        sb_write_s16(b, arg.value_s16);
        break;
    case ARG_TYPE_S32:
        sb_write_s32(b, arg.value_s32);
        break;
    case ARG_TYPE_S64:
        sb_write_s64(b, arg.value_s64);
        break;
    case ARG_TYPE_B8:
        sb_write_b8(b, arg.value_b8);
        break;
    case ARG_TYPE_STR:
        sb_write_str(b, arg.value_str);
        break;
    case ARG_TYPE_PU8:
    case ARG_TYPE_PU16:
    case ARG_TYPE_PU32:
    case ARG_TYPE_PU64:
    case ARG_TYPE_PS8:
    case ARG_TYPE_PS16:
    case ARG_TYPE_PS32:
    case ARG_TYPE_PS64:
    case ARG_TYPE_PB8:
    case ARG_TYPE_PSTR:
        sb_write_str(b, S("0x"));
        sb_push_mod(b, ENCODING_HEXL);
            sb_write_str(b, (string) { (char*) &arg.value_pu8, sizeof(arg.value_pu8) });
        sb_pop_mod(b);
        break;
    }
}

static b8 is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static int parse_placeholder(char *src, int len, int *pcur)
{
    int cur = *pcur;

    if (cur == len || src[cur] != '{')
        return -1;
    cur++; // Skip '{'

    s32 argidx = -2;
    if (cur < len && is_digit(src[cur])) {
        argidx = src[cur] - '0';
        cur++;
        while (cur < len && is_digit(src[cur])) {
            s32 d = src[cur] - '0';
            cur++;
            if (argidx > (S32_MAX - d) / 10)
                return -1;
            argidx = argidx * 10 + d;
        }
    }

    if (cur == len || src[cur] != '}')
        return -1;
    cur++; // Skip '}'

    *pcur = cur;
    return argidx;
}

void sb_write_fmt(StringBuilder *b, string fmt, Args args)
{
    char *src = fmt.ptr;
    int   len = fmt.len;
    int   cur = 0;
    int   nextarg = 0;

    for (;;) {

        int off = cur;
        while (cur < len && src[cur] != '{')
            cur++;

        sb_write_str(b, (string) { src + off, cur - off });

        if (cur == len)
            break;
        ASSERT(src[cur] == '{');

        int oldcur = cur;
        int argidx = parse_placeholder(src, len, &cur);

        if (argidx == -1) {
            cur = oldcur;
            continue; // Error
        }

        if (argidx == -2)
            argidx = nextarg++;

        if (nextarg >= args.len) {
            cur = oldcur;
            continue;
        }

        Arg arg = args.ptr[argidx];
        sb_write_arg(b, arg);
    }
}

void sb_push_mod(StringBuilder *b, Encoding m)
{
    ASSERT(b->num_mods < SB_MODIFIER_LIMIT);

    b->mods[b->num_mods].type = m;
    b->mods[b->num_mods].off_0 = b->len;
    b->mods[b->num_mods].off_1 = -1;
    b->num_mods++;
}

void sb_flush(StringBuilder *b)
{
    if (b->status != 0)
        return;

    ASSERT(b->num_mods > 0);
    ASSERT(b->mods[b->num_mods-1].type == ENCODING_HMAC);
    ASSERT(b->mods[b->num_mods-1].off_1 == -1);

    b->mods[b->num_mods-1].off_1 = b->len;
}

void sb_pop_mod(StringBuilder *b)
{
    ASSERT(b->num_mods > 0);
    SB_Modifier mod = b->mods[--b->num_mods];

    int len1, len2;
    if (mod.type == ENCODING_HMAC) {
        len1 = mod.off_1 - mod.off_0;
        len2 = b->len - mod.off_1;
    } else {
        len1 = b->len - mod.off_0;
        len2 = 0;
    }

    int olen = encode_len(b->dst + mod.off_0, len1, len2, mod.type);
    if (olen < 0) {
        b->status = SB_LIB_ERROR;
        return;
    }

    if (olen > b->cap - mod.off_0 && b->status == 0)
        b->status = SB_OUT_OF_MEMORY;

    if (b->status == 0) {
        int ret = encode_inplace(b->dst + mod.off_0, len1, len2,
                                 b->cap - mod.off_0, mod.type);
        if (ret < 0)
            b->status = SB_LIB_ERROR;
    }

    b->len = mod.off_0 + olen;
}
