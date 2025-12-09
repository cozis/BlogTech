#include "string_builder.h"

void sb_init(StringBuilder *b, char *dst, int cap)
{
    b->dst = dst;
    b->cap = cap;
    b->len = 0;
    b->num_mods = 0;
    b->status = 0;
}

#ifdef SB_TRACE
static void dump(StringBuilder *builder, char *file, int line)
{
    printf("%s:%d\n", file, line);
    switch (builder->status) {
    case 0:
        printf("  status=OK\n");
        break;
    case SB_OUT_OF_MEMORY:
        printf("  status=OUT_OF_MEMORY\n");
        break;
    case SB_LIB_ERROR:
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
            if ((u8) c < 32 || (u8) c > 127)
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

void sb_write_(StringBuilder *b, string s, char *file, int line)
{
    if (b->status == 0) {
        if (b->cap - b->len < s.len) {
            b->status = SB_OUT_OF_MEMORY;
        } else {
            memcpy_(b->dst + b->len, s.ptr, s.len);
        }
    }
    b->len += s.len;

#ifdef SB_TRACE
    dump(b, file, line);
#else
    (void) file;
    (void) line;
#endif
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

void sb_pop_mod_(StringBuilder *b, char *file, int line)
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

#ifdef SB_TRACE
    dump(b, file, line);
#else
    (void) file;
    (void) line;
#endif
}
