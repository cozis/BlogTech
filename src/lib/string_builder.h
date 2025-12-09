#ifndef STRING_BUILDER_INCLUDED
#define STRING_BUILDER_INCLUDED

#include "basic.h"
#include "encode.h"

// If the output is not being created correctly,
// uncomment this do dump the state of the builder
// at each step:
//
//    #define SB_TRACE

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
void sb_write_(StringBuilder *b, string s, char *file, int line);
void sb_flush(StringBuilder *b);
void sb_push_mod(StringBuilder *b, Encoding m);
void sb_pop_mod_(StringBuilder *b, char *file, int line);

#ifdef SB_TRACE

#define sb_write(b, s) \
    sb_write_(b, s, __FILE__, __LINE__)

#define sb_pop_mod(b) \
    sb_pop_mod_(b, __FILE__, __LINE__)

#else

#define sb_write(b, s) \
    sb_write_(b, s, NULL, 0)

#define sb_pop_mod(b) \
    sb_pop_mod_(b, NULL, 0)

#endif

#endif // STRING_BUILDER_INCLUDED
