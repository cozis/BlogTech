#include "variadic.h"

Arg init_arg_u8  (u8  value) { return (Arg) { .type=ARG_TYPE_U8,  .value_u8=value }; }
Arg init_arg_u16 (u16 value) { return (Arg) { .type=ARG_TYPE_U16, .value_u16=value }; }
Arg init_arg_u32 (u32 value) { return (Arg) { .type=ARG_TYPE_U32, .value_u32=value }; }
Arg init_arg_u64 (u64 value) { return (Arg) { .type=ARG_TYPE_U64, .value_u64=value }; }
Arg init_arg_s8  (s8  value) { return (Arg) { .type=ARG_TYPE_S8, .value_s8=value }; }
Arg init_arg_s16 (s16 value) { return (Arg) { .type=ARG_TYPE_S16, .value_s16=value }; }
Arg init_arg_s32 (s32 value) { return (Arg) { .type=ARG_TYPE_S32, .value_s32=value }; }
Arg init_arg_s64 (s64 value) { return (Arg) { .type=ARG_TYPE_S64, .value_s64=value }; }
Arg init_arg_b8  (b8  value) { return (Arg) { .type=ARG_TYPE_B8, .value_b8=value }; }
Arg init_arg_str (string value) { return (Arg) { .type=ARG_TYPE_STR, .value_str=value }; }
Arg init_arg_pu8 (u8  *value) { return (Arg) { .type=ARG_TYPE_PU8, .value_pu8=value }; }
Arg init_arg_pu16(u16 *value) { return (Arg) { .type=ARG_TYPE_PU16, .value_pu16=value }; }
Arg init_arg_pu32(u32 *value) { return (Arg) { .type=ARG_TYPE_PU32, .value_pu32=value }; }
Arg init_arg_pu64(u64 *value) { return (Arg) { .type=ARG_TYPE_PU64, .value_pu64=value }; }
Arg init_arg_ps8 (s8  *value) { return (Arg) { .type=ARG_TYPE_PS8, .value_ps8=value }; }
Arg init_arg_ps16(s16 *value) { return (Arg) { .type=ARG_TYPE_PS16, .value_ps16=value }; }
Arg init_arg_ps32(s32 *value) { return (Arg) { .type=ARG_TYPE_PS32, .value_ps32=value }; }
Arg init_arg_ps64(s64 *value) { return (Arg) { .type=ARG_TYPE_PS64, .value_ps64=value }; }
Arg init_arg_pb8 (b8  *value) { return (Arg) { .type=ARG_TYPE_PB8, .value_pb8=value }; }
Arg init_arg_pstr(string *value)  { return (Arg) { .type=ARG_TYPE_PSTR, .value_pstr=value }; }
