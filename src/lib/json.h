#ifndef JSON_INCLUDED
#define JSON_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "basic.h"

/////////////////////////////////////////////////////////
// BASICS
/////////////////////////////////////////////////////////

// Utility string type
#define JSON_String string

// Translate string literal to JSON_String
#define JSON_STR(X) ((JSON_String) { (X), (int) sizeof(X)-1 })

typedef struct {
    char msg[100];
} JSON_Error;

typedef struct {
    char  *last;
    char  *ptr;
    size_t len;
    size_t cur;
} JSON_Arena;

JSON_Arena json_arena_init(char *ptr, size_t len);

/////////////////////////////////////////////////////////
// DECODE
/////////////////////////////////////////////////////////

// Type tag for the JSON struct
typedef enum {
    JSON_TYPE_BOOL,
    JSON_TYPE_NULL,
    JSON_TYPE_OBJECT,
    JSON_TYPE_ARRAY,
    JSON_TYPE_FLOAT,
    JSON_TYPE_INT,
    JSON_TYPE_STRING,
} JSON_Type;

// This represents a "JSON value"
//
// Although there are helper functions to access
// data from JSON values, accessing these fields
// directly is allowed.
typedef struct JSON JSON;
struct JSON {

    // If this value is contained by an object
    // or array, this points to the next item
    // that object or array. If NULL, this is
    // the last element.
    JSON *next;

    // Type encoded by this struct
    JSON_Type type;

    // If this value is contained by an object,
    // this pointer and length encode the key
    // associated to this value in that object.
    // If the value is not contained by an object,
    // the key is NULL and the length is 0.
    char *key;
    size_t key_len;

    // Number of elements contained by this
    // array. The meaning on this field depends
    // on the type encoded by this struct:
    //   string -> number of characters
    //   object -> number of key-value pairs
    //   array  -> number of items
    // For any other type, this is set to 0.
    size_t len;

    union {

        // Pointer to the first child value when the
        // type of this value is array or object
        JSON *head;

        // Floating-point value
        double fval;

        // Integer value
        int64_t ival;

        // String value
        //
        // This is not null-terminated. The length is
        // stored in the "len" field.
        char *sval;

        // Boolean value
        bool bval;
    };
};

JSON *json_decode(char *src, int len, JSON_Arena *arena, JSON_Error *error);

/////////////////////////////////////////////////////////
// UTILITIES
/////////////////////////////////////////////////////////

// Returns a human-readable version of the type
const char *json_type_name(JSON_Type type);

// Return the type of a JSON value.
//
// The argument can't be NULL.
JSON_Type json_get_type(JSON *json);

// Return the key associated to a JSON value.
//
// This operation is only valid if the value is
// contained by an object JSON value.
JSON_String json_get_key(JSON *json);

// Return the boolean value associated to this
// JSON value.
//
// If the value is NULL or not a boolean, the
// fallback value is returned.
bool json_get_bool(JSON *json, bool fallback);

// Return the integer value associated to this
// JSON value.
//
// If the value is NULL or not an integer, the
// fallback value is returned.
int64_t json_get_int(JSON *json, int64_t fallback);

// Return the floating point value associated to
// this JSON value.
//
// If the value is NULL or not an double, the
// fallback value is returned.
double json_get_float(JSON *json, double fallback);

// Return the string value associated to this
// JSON value.
//
// If the value is NULL or not a string, the
// empty string is returned.
JSON_String json_get_string(JSON *json);

// Return the children of an object with the
// specified key.
//
// If the value is NULL, not an object, or does
// not contain the key, NULL is returned.
JSON *json_get_field(JSON *obj, JSON_String key);

// Note that there is no helper method for accessing
// array values. To iterate over an array JSON value,
// you need to follow the next pointers:
//
//   JSON *array = ...;
//   for (JSON *child = array->head; child; child = child->next) {
//     ...
//   }

/////////////////////////////////////////////////////////
// INTERNAL
/////////////////////////////////////////////////////////

#define __JSON_HELPER_ARG(X)                 \
    _Generic((X),                            \
        bool*       : json_match_arg_bool,   \
        int64_t*    : json_match_arg_int,    \
        double*     : json_match_arg_float,  \
        JSON_String*: json_match_arg_string, \
        JSON**      : json_match_arg_any     \
    )(X)

// Helper macros
#define __JSON_HELPER_DISPATCH_N(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, N, ...) N
#define __JSON_HELPER_CONCAT_0(A, B) A ## B
#define __JSON_HELPER_CONCAT_1(A, B) __JSON_HELPER_CONCAT_0(A, B)
#define __JSON_HELPER_ARGS_0()                       (JSON_MatchArgs) { 0, (JSON_MatchArg[]) {}}
#define __JSON_HELPER_ARGS_1(a)                      (JSON_MatchArgs) { 1, (JSON_MatchArg[]) { __JSON_HELPER_ARG(a) }}
#define __JSON_HELPER_ARGS_2(a, b)                   (JSON_MatchArgs) { 2, (JSON_MatchArg[]) { __JSON_HELPER_ARG(a), __JSON_HELPER_ARG(b) }}
#define __JSON_HELPER_ARGS_3(a, b, c)                (JSON_MatchArgs) { 3, (JSON_MatchArg[]) { __JSON_HELPER_ARG(a), __JSON_HELPER_ARG(b), __JSON_HELPER_ARG(c) }}
#define __JSON_HELPER_ARGS_4(a, b, c, d)             (JSON_MatchArgs) { 4, (JSON_MatchArg[]) { __JSON_HELPER_ARG(a), __JSON_HELPER_ARG(b), __JSON_HELPER_ARG(c), __JSON_HELPER_ARG(d) }}
#define __JSON_HELPER_ARGS_5(a, b, c, d, e)          (JSON_MatchArgs) { 5, (JSON_MatchArg[]) { __JSON_HELPER_ARG(a), __JSON_HELPER_ARG(b), __JSON_HELPER_ARG(c), __JSON_HELPER_ARG(d), __JSON_HELPER_ARG(e) }}
#define __JSON_HELPER_ARGS_6(a, b, c, d, e, f)       (JSON_MatchArgs) { 6, (JSON_MatchArg[]) { __JSON_HELPER_ARG(a), __JSON_HELPER_ARG(b), __JSON_HELPER_ARG(c), __JSON_HELPER_ARG(d), __JSON_HELPER_ARG(e), __JSON_HELPER_ARG(f) }}
#define __JSON_HELPER_ARGS_7(a, b, c, d, e, f, g)    (JSON_MatchArgs) { 7, (JSON_MatchArg[]) { __JSON_HELPER_ARG(a), __JSON_HELPER_ARG(b), __JSON_HELPER_ARG(c), __JSON_HELPER_ARG(d), __JSON_HELPER_ARG(e), __JSON_HELPER_ARG(f), __JSON_HELPER_ARG(g) }}
#define __JSON_HELPER_ARGS_8(a, b, c, d, e, f, g, h) (JSON_MatchArgs) { 8, (JSON_MatchArg[]) { __JSON_HELPER_ARG(a), __JSON_HELPER_ARG(b), __JSON_HELPER_ARG(c), __JSON_HELPER_ARG(d), __JSON_HELPER_ARG(e), __JSON_HELPER_ARG(f), __JSON_HELPER_ARG(g), __JSON_HELPER_ARG(h) }}
#define __JSON_COUNT_ARGS(...) __JSON_HELPER_DISPATCH_N(DUMMY, ##__VA_ARGS__, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define JSON_MATCH_ARGS(...) __JSON_HELPER_CONCAT_1(__JSON_HELPER_ARGS_, __JSON_COUNT_ARGS(__VA_ARGS__))(__VA_ARGS__)

/////////////////////////////////////////////////////////
// PATTERN MATCHING
/////////////////////////////////////////////////////////

typedef enum {
    JSON_MATCH_ARG_TYPE_BOOL,
    JSON_MATCH_ARG_TYPE_INT,
    JSON_MATCH_ARG_TYPE_FLOAT,
    JSON_MATCH_ARG_TYPE_STRING,
    JSON_MATCH_ARG_TYPE_ANY,
} JSON_MatchArgType;

typedef struct {
    JSON_MatchArgType type;
    union {
        bool        *bptr;
        int64_t     *iptr;
        double      *fptr;
        JSON_String *sptr;
        JSON        **anyptr;
    };
} JSON_MatchArg;

typedef struct {
    int len;
    JSON_MatchArg *ptr;
} JSON_MatchArgs;

// Returns:
//   0 Pattern matched
//   1 Pattern didn't match
//  -1 Invalid pattern
int json_match_impl(JSON *json, JSON_Error *err, char *pattern, JSON_MatchArgs args);

#define json_match(json, err, pattern, ...) \
    json_match_impl((json), (err), (pattern), JSON_MATCH_ARGS(__VA_ARGS__))

// Don't use these directly
JSON_MatchArg json_match_arg_bool  (bool        *x);
JSON_MatchArg json_match_arg_int   (int64_t     *x);
JSON_MatchArg json_match_arg_float (double      *x);
JSON_MatchArg json_match_arg_string(JSON_String *x);
JSON_MatchArg json_match_arg_any   (JSON       **x);

/////////////////////////////////////////////////////////
// STRING ESCAPING
/////////////////////////////////////////////////////////

JSON_String json_escape(JSON_Arena *arena, JSON_String str);

/////////////////////////////////////////////////////////
// END
/////////////////////////////////////////////////////////
#endif // JSON_INCLUDED
