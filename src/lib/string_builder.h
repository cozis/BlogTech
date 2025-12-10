#ifndef STRING_BUILDER_INCLUDED
#define STRING_BUILDER_INCLUDED

#include "basic.h"
#include "encode.h"
#include "variadic.h"

// Error codes for the builder
enum {
    SB_OUT_OF_MEMORY = -1,
    SB_LIB_ERROR     = -2,
};

#define SB_MODIFIER_LIMIT 32

typedef struct {
    Encoding type;
    int off_0;
    int off_1;
} SB_Modifier;

typedef struct {
    char *dst;
    int   cap;
    int   len;
    int status;
    int num_mods;
    SB_Modifier mods[SB_MODIFIER_LIMIT];
} StringBuilder;

void sb_init(StringBuilder *b, char *dst, int cap);
void sb_write_u8(StringBuilder *b, u8 v);
void sb_write_u16(StringBuilder *b, u16 v);
void sb_write_u32(StringBuilder *b, u32 v);
void sb_write_u64(StringBuilder *b, u64 v);
void sb_write_s8(StringBuilder *b, s8 v);
void sb_write_s16(StringBuilder *b, s16 v);
void sb_write_s32(StringBuilder *b, s32 v);
void sb_write_s64(StringBuilder *b, s64 v);
void sb_write_b8(StringBuilder *b, b8 v);
void sb_write_str(StringBuilder *b, string s);
void sb_write_arg(StringBuilder *b, Arg arg);
void sb_write_fmt(StringBuilder *b, string fmt, Args args);
void sb_flush(StringBuilder *b);
void sb_push_mod(StringBuilder *b, Encoding m);
void sb_pop_mod(StringBuilder *b);

string fmtorempty(string fmt, Args args, char *buf, int cap);

#endif // STRING_BUILDER_INCLUDED
