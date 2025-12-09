#ifndef BASIC_INCLUDED
#define BASIC_INCLUDED
/////////////////////////////////////////////////////////////////////////
// HELPER MACROS
/////////////////////////////////////////////////////////////////////////

#define NULL ((void*) 0)
#define COUNT(X) (int) (sizeof(X) / sizeof((X)[0]))
#define SIZEOF(X) (int) sizeof(X)

/////////////////////////////////////////////////////////////////////////
// ASSERTIONS
/////////////////////////////////////////////////////////////////////////

#ifdef NDEBUG
#define UNREACHABLE
#else
#define UNREACHABLE __builtin_trap()
#endif

#ifdef NDEBUG
#define ASSERT(X) {}
#else
#define ASSERT(X) { if (!(x)) __builtin_trap(); }
#endif

#define STATIC_ASSERT _Static_assert

/////////////////////////////////////////////////////////////////////////
// INTEGER TYPES
/////////////////////////////////////////////////////////////////////////

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;

typedef signed char        s8;
typedef signed short       s16;
typedef signed int         s32;
typedef signed long long   s64;

STATIC_ASSERT(sizeof(u8)  == 1);
STATIC_ASSERT(sizeof(u16) == 2);
STATIC_ASSERT(sizeof(u32) == 4);
STATIC_ASSERT(sizeof(u64) == 8);

STATIC_ASSERT(sizeof(s8)  == 1);
STATIC_ASSERT(sizeof(s16) == 2);
STATIC_ASSERT(sizeof(s32) == 4);
STATIC_ASSERT(sizeof(s64) == 8);

#define U8_MAX (~(u8) 0)
#define U8_MIN 0

#define U16_MAX (~(u16) 0)
#define U16_MIN 0

#define U32_MAX (~(u32) 0)
#define U32_MIN 0

#define U64_MAX (~(u64) 0)
#define U64_MIN 0

/////////////////////////////////////////////////////////////////////////
// BOOLEAN TYPE
/////////////////////////////////////////////////////////////////////////

typedef unsigned char bool;

STATIC_ASSERT(sizeof(bool) == 1);

#define true  ((bool) 1)
#define false ((bool) 0)

/////////////////////////////////////////////////////////////////////////
// STRING TYPE
/////////////////////////////////////////////////////////////////////////

typedef struct {
    char *ptr;
    int   len;
} string;

#define S(X) (string) { (X), sizeof(X)-1 }
#define UNPACK(S) (S).len, (S).ptr
#define EMPTY_STRING (string) { NULL, 0 }

bool   streq(string s1, string s2);
bool   streqcase(string s1, string s2);
string allocstr(string s);

/////////////////////////////////////////////////////////////////////////
#endif // BASIC_INCLUDED
