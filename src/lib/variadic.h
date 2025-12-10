#ifndef VARIADIC_INCLUDED
#define VARIADIC_INCLUDED

#include "basic.h"

#define __HELPER_ARG(X)          \
    _Generic((X),                \
        u8      : init_arg_u8,   \
        u16     : init_arg_u16,  \
        u32     : init_arg_u32,  \
        u64     : init_arg_u64,  \
        s8      : init_arg_s8,   \
        s16     : init_arg_s16,  \
        s32     : init_arg_s32,  \
        s64     : init_arg_s64,  \
        b8      : init_arg_b8,   \
        string  : init_arg_str,  \
        u8     *: init_arg_pu8,  \
        u16    *: init_arg_pu16, \
        u32    *: init_arg_pu32, \
        u64    *: init_arg_pu64, \
        s8     *: init_arg_ps8,  \
        s16    *: init_arg_ps16, \
        s32    *: init_arg_ps32, \
        s64    *: init_arg_ps64, \
        b8     *: init_arg_pb8,  \
        string *: init_arg_pstr  \
    )(X)

// Helper macros
#define __HELPER_DISPATCH_N(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, N, ...) N
#define __HELPER_CONCAT_0(A, B) A ## B
#define __HELPER_CONCAT_1(A, B) __HELPER_CONCAT_0(A, B)
#define __HELPER_ARGS_0()                       (Args) { 0, (Arg[]) {}}
#define __HELPER_ARGS_1(a)                      (Args) { 1, (Arg[]) { __HELPER_ARG(a) }}
#define __HELPER_ARGS_2(a, b)                   (Args) { 2, (Arg[]) { __HELPER_ARG(a), __HELPER_ARG(b) }}
#define __HELPER_ARGS_3(a, b, c)                (Args) { 3, (Arg[]) { __HELPER_ARG(a), __HELPER_ARG(b), __HELPER_ARG(c) }}
#define __HELPER_ARGS_4(a, b, c, d)             (Args) { 4, (Arg[]) { __HELPER_ARG(a), __HELPER_ARG(b), __HELPER_ARG(c), __HELPER_ARG(d) }}
#define __HELPER_ARGS_5(a, b, c, d, e)          (Args) { 5, (Arg[]) { __HELPER_ARG(a), __HELPER_ARG(b), __HELPER_ARG(c), __HELPER_ARG(d), __HELPER_ARG(e) }}
#define __HELPER_ARGS_6(a, b, c, d, e, f)       (Args) { 6, (Arg[]) { __HELPER_ARG(a), __HELPER_ARG(b), __HELPER_ARG(c), __HELPER_ARG(d), __HELPER_ARG(e), __HELPER_ARG(f) }}
#define __HELPER_ARGS_7(a, b, c, d, e, f, g)    (Args) { 7, (Arg[]) { __HELPER_ARG(a), __HELPER_ARG(b), __HELPER_ARG(c), __HELPER_ARG(d), __HELPER_ARG(e), __HELPER_ARG(f), __HELPER_ARG(g) }}
#define __HELPER_ARGS_8(a, b, c, d, e, f, g, h) (Args) { 8, (Arg[]) { __HELPER_ARG(a), __HELPER_ARG(b), __HELPER_ARG(c), __HELPER_ARG(d), __HELPER_ARG(e), __HELPER_ARG(f), __HELPER_ARG(g), __HELPER_ARG(h) }}
#define __COUNT_ARGS(...) __HELPER_DISPATCH_N(DUMMY, ##__VA_ARGS__, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define V(...) __HELPER_CONCAT_1(__HELPER_ARGS_, __COUNT_ARGS(__VA_ARGS__))(__VA_ARGS__)

typedef enum {
    ARG_TYPE_U8,
    ARG_TYPE_U16,
    ARG_TYPE_U32,
    ARG_TYPE_U64,
    ARG_TYPE_S8,
    ARG_TYPE_S16,
    ARG_TYPE_S32,
    ARG_TYPE_S64,
    ARG_TYPE_B8,
    ARG_TYPE_STR,
    ARG_TYPE_PU8,
    ARG_TYPE_PU16,
    ARG_TYPE_PU32,
    ARG_TYPE_PU64,
    ARG_TYPE_PS8,
    ARG_TYPE_PS16,
    ARG_TYPE_PS32,
    ARG_TYPE_PS64,
    ARG_TYPE_PB8,
    ARG_TYPE_PSTR,
} ArgType;

typedef struct {
    ArgType type;
    union {
        u8      value_u8;
        u16     value_u16;
        u32     value_u32;
        u64     value_u64;
        s8      value_s8;
        s16     value_s16;
        s32     value_s32;
        s64     value_s64;
        b8      value_b8;
        string  value_str;
        u8     *value_pu8;
        u16    *value_pu16;
        u32    *value_pu32;
        u64    *value_pu64;
        s8     *value_ps8;
        s16    *value_ps16;
        s32    *value_ps32;
        s64    *value_ps64;
        b8     *value_pb8;
        string *value_pstr;
    };
} Arg;

typedef struct {
    int len;
    Arg *ptr;
} Args;

Arg init_arg_u8  (u8  value);
Arg init_arg_u16 (u16 value);
Arg init_arg_u32 (u32 value);
Arg init_arg_u64 (u64 value);
Arg init_arg_s8  (s8  value);
Arg init_arg_s16 (s16 value);
Arg init_arg_s32 (s32 value);
Arg init_arg_s64 (s64 value);
Arg init_arg_b8  (b8  value);
Arg init_arg_str (string value);
Arg init_arg_pu8 (u8  *value);
Arg init_arg_pu16(u16 *value);
Arg init_arg_pu32(u32 *value);
Arg init_arg_pu64(u64 *value);
Arg init_arg_ps8 (s8  *value);
Arg init_arg_ps16(s16 *value);
Arg init_arg_ps32(s32 *value);
Arg init_arg_ps64(s64 *value);
Arg init_arg_pb8 (b8  *value);
Arg init_arg_pstr(string *value);

#endif // VARIADIC_INCLUDED
