#ifndef BASIC_INCLUDED
#define BASIC_INCLUDED
/////////////////////////////////////////////////////////////////////////
// HELPER MACROS
/////////////////////////////////////////////////////////////////////////

#ifndef NULL
#define NULL ((void*) 0)
#endif

#define COUNT(X) (int) (sizeof(X) / sizeof((X)[0]))
#define SIZEOF(X) (int) sizeof(X)
#define CEIL(X, Y) (((X) + (Y) - 1) / (Y))

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
#define ASSERT(X) { if (!(X)) __builtin_trap(); }
#endif

#define STATIC_ASSERT(X) _Static_assert((X), "")

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

// TODO: check the following macros

#define U8_MAX ((u8) ~(u8) 0)
#define U8_MIN 0

#define U16_MAX ((u16) ~(u16) 0)
#define U16_MIN 0

#define U32_MAX ((u32) ~(u32) 0)
#define U32_MIN 0

#define U64_MAX ((u64) ~(u64) 0)
#define U64_MIN 0

#define S8_MAX ((s8) ((~(u8) 0) / 2))
#define S8_MIN ((s8) (-(~(u8) 0) / 2 - 1))

#define S16_MAX ((s16) ((~(u16) 0) / 2))
#define S16_MIN ((s16) (-(~(u16) 0) / 2 - 1))

#define S32_MAX ((s32) ((~(u32) 0) / 2))
#define S32_MIN ((s32) (-(~(u32) 0) / 2 - 1))

#define S64_MAX ((s64) ((~(u64) 0) / 2))
#define S64_MIN ((s64) (-(~(u64) 0) / 2 - 1))

/////////////////////////////////////////////////////////////////////////
// BOOLEAN TYPE
/////////////////////////////////////////////////////////////////////////

typedef char b8;

STATIC_ASSERT(sizeof(b8) == 1);

#ifdef true
#undef true
#endif

#ifdef false
#undef false
#endif

#define true  ((b8) 1)
#define false ((b8) 0)

/////////////////////////////////////////////////////////////////////////
// STRING TYPE
/////////////////////////////////////////////////////////////////////////

typedef struct {
    char *ptr;
    int   len;
} string;

#define S(X) (string) { (X), sizeof(X)-1 }
#define ZT2S(X) (string) { (X), strlen_(X) }
#define UNPACK(S) (S).len, (S).ptr
#define EMPTY_STRING (string) { NULL, 0 }

b8     streq(string s1, string s2);
b8     streqcase(string s1, string s2);
string allocstr(string s);
void   memcpy_(char *dst, char *src, int len);
string trim(string s);

/////////////////////////////////////////////////////////////////////////
// PRIVATE USE FOR MACROS
/////////////////////////////////////////////////////////////////////////

int strlen_(char *p);

/////////////////////////////////////////////////////////////////////////
#endif // BASIC_INCLUDED
