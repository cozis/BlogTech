#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include "json.h"

////////////////////////////////////////////////////////////////////
// PARSER
////////////////////////////////////////////////////////////////////

typedef struct {
    char*  src;
    size_t len;
    size_t cur;
    JSON_Arena *arena;
    JSON_Error *error;
} Context;

static bool is_wspace(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static bool is_control(char c)
{
    return c >= 0 && c < ' '; // TODO: is this correct?
}

static void consume_wspace(Context *ctx)
{
    while (ctx->cur < ctx->len && is_wspace(ctx->src[ctx->cur]))
        ctx->cur++;
}

static void *alloc(JSON_Arena *arena, size_t len, size_t align)
{
    size_t pad = -(uintptr_t) (arena->ptr + arena->cur) & (align-1);

    if (arena->len - arena->cur < len + pad)
        return NULL;

    arena->cur += pad;
    void *ptr = arena->ptr + arena->cur;

    arena->cur += len;
    arena->last = ptr;
    return ptr;
}

static bool grow_alloc(JSON_Arena *arena, void *ptr, size_t new_len)
{
    if (ptr == NULL || arena->last != ptr)
        return false;

    size_t old_len = (arena->ptr + arena->cur) - arena->last;
    if (new_len < old_len)
        return false;

    size_t increase_len = new_len - old_len;
    if (arena->len - arena->cur < increase_len)
        return false;

    arena->cur += increase_len;
    return true;
}

typedef struct {
    JSON_Arena *arena;
    char*       ptr;
    size_t      len;
    bool        err;
} GrowingBuffer;

static GrowingBuffer gbinit(JSON_Arena *arena)
{
    return (GrowingBuffer) { arena, NULL, 0, false };
}

static void gbappends(GrowingBuffer *gb, char *str, size_t len)
{
    if (gb->err)
        return;

    if (len == 0)
        return;

    if (gb->ptr == NULL) {
        gb->ptr = alloc(gb->arena, len, 1);
        if (gb->ptr == NULL) {
            gb->err = true;
            return;
        }
    } else {
        if (!grow_alloc(gb->arena, gb->ptr, gb->len + len)) {
            gb->err = true;
            return;
        }
    }

    memcpy(gb->ptr + gb->len, str, len);
    gb->len += len;
}

static void gbappendc(GrowingBuffer *gb, char c)
{
    gbappends(gb, &c, 1);
}

static JSON *parse_any(Context *ctx);

static void
consume_unescaped_string_contents(Context *ctx)
{
    while (ctx->cur < ctx->len
        && ctx->src[ctx->cur] != '"'
        && ctx->src[ctx->cur] != '\\'
        && !is_control(ctx->src[ctx->cur]))
        ctx->cur++;
}

static char *parse_string_raw(Context *ctx, size_t *plen)
{
    assert(ctx->cur < ctx->len && ctx->src[ctx->cur] == '"');
    ctx->cur++;

    GrowingBuffer gb = gbinit(ctx->arena);

    for (;;) {

        size_t off = ctx->cur;
        consume_unescaped_string_contents(ctx);

        gbappends(&gb,
            ctx->src + off,
            ctx->cur - off
        );

        if (ctx->cur == ctx->len)
            return NULL;

        char c = ctx->src[ctx->cur++];

        if (is_control(c))
            return NULL;

        if (c == '"')
            break;

        assert(c == '\\');

        if (ctx->cur == ctx->len)
            return NULL;
        c = ctx->src[ctx->cur++];

        switch (c) {
            case '"':  gbappendc(&gb, '"');  break;
            case '\\': gbappendc(&gb, '\\'); break;
            case '/':  gbappendc(&gb, '/');  break;
            case 'b':  gbappendc(&gb, '\b'); break;
            case 'f':  gbappendc(&gb, '\f'); break;
            case 'n':  gbappendc(&gb, '\n'); break;
            case 'r':  gbappendc(&gb, '\r'); break;
            case 't':  gbappendc(&gb, '\t'); break;

            case 'u':
            // TODO: not implemented yet
            return NULL;

            default:
            return NULL;
        }
    }

    if (gb.err)
        return NULL;

    *plen = gb.len;
    return gb.ptr;
}

static JSON *parse_string(Context *ctx)
{
    size_t len;
    char *ptr = parse_string_raw(ctx, &len);
    if (ptr == NULL)
        return NULL;

    JSON *val = alloc(ctx->arena, sizeof(JSON), _Alignof(JSON));
    if (val == NULL)
        return NULL;
    val->type = JSON_TYPE_STRING;
    val->len  = len;
    val->sval = ptr;

    return val;
}

static bool node_with_key_exists(JSON *head, char *key, size_t key_len)
{
    if (head == NULL)
        return false;

    JSON *cursor = head;
    while (cursor) {

        if (cursor->key_len == key_len && memcmp(cursor->key, key, key_len) == 0)
            return true;

        cursor = cursor->next;
    }

    return false;
}

static JSON *parse_object(Context *ctx)
{
    assert(ctx->cur < ctx->len && ctx->src[ctx->cur] == '{');
    ctx->cur++;

    consume_wspace(ctx);

    int count = 0;
    JSON *head = NULL;
    JSON **tail = &head;

    if (ctx->src[ctx->cur] != '}') {

        for (;;) {

            if (ctx->cur == ctx->len || ctx->src[ctx->cur] != '"')
                return NULL;

            size_t key_len;
            char *key = parse_string_raw(ctx, &key_len);
            if (key == NULL)
                return NULL;

            if (node_with_key_exists(head, key, key_len))
                return NULL;

            consume_wspace(ctx);

            if (ctx->cur == ctx->len || ctx->src[ctx->cur] != ':')
                return NULL;
            ctx->cur++;

            consume_wspace(ctx);

            JSON *val = parse_any(ctx);
            if (val == NULL)
                return NULL;

            val->next = NULL;
            val->key = key;
            val->key_len = key_len;

            *tail = val;
            tail = &val->next;
            count++;

            consume_wspace(ctx);

            if (ctx->cur == ctx->len)
                return NULL;

            if (ctx->src[ctx->cur] == '}')
                break;

            if (ctx->src[ctx->cur] != ',')
                return NULL;
            ctx->cur++;

            consume_wspace(ctx);
        }
    }

    assert(ctx->cur < ctx->len && ctx->src[ctx->cur] == '}');
    ctx->cur++;

    JSON *obj = alloc(ctx->arena, sizeof(JSON), _Alignof(JSON));
    if (obj == NULL)
        return NULL;
    obj->type = JSON_TYPE_OBJECT;
    obj->len  = (size_t) count;
    obj->head = head;

    return obj;
}

static JSON *parse_array(Context *ctx)
{
    assert(ctx->cur < ctx->len && ctx->src[ctx->cur] == '[');
    ctx->cur++;

    consume_wspace(ctx);

    int count = 0;
    JSON *head = NULL;
    JSON **tail = &head;

    if (ctx->src[ctx->cur] != ']') {

        for (;;) {

            JSON *val = parse_any(ctx);
            if (val == NULL)
                return NULL;

            val->next = NULL;
            val->key = NULL;
            val->key_len = 0;

            *tail = val;
            tail = &val->next;
            count++;

            consume_wspace(ctx);

            if (ctx->cur == ctx->len)
                return NULL;

            if (ctx->src[ctx->cur] == ']')
                break;

            if (ctx->src[ctx->cur] != ',')
                return NULL;
            ctx->cur++;

            consume_wspace(ctx);
        }
    }

    assert(ctx->cur < ctx->len && ctx->src[ctx->cur] == ']');
    ctx->cur++;

    JSON *arr = alloc(ctx->arena, sizeof(JSON), _Alignof(JSON));
    if (arr == NULL)
        return NULL;
    arr->type = JSON_TYPE_ARRAY;
    arr->len  = (size_t) count;
    arr->head = head;

    return arr;
}

static JSON *parse_float(Context *ctx)
{
    bool neg = false;
    if (ctx->src[ctx->cur] == '-') {
        ctx->cur++;
        if (ctx->cur == ctx->len || !is_digit(ctx->src[ctx->cur]))
            return NULL;
        neg = true;
    }

    double x = 0;
    do {
        assert(ctx->cur < ctx->len && is_digit(ctx->src[ctx->cur]));
        int d = ctx->src[ctx->cur++] - '0';
        if (neg) d = -d;
        x *= 10;
        x += d;
    } while (ctx->src[ctx->cur] != '.');

    // Consume dot
    ctx->cur++;

    if (ctx->cur == ctx->len || !is_digit(ctx->src[ctx->cur]))
        return NULL;

    double s = 0.1;
    do {
        int d = ctx->src[ctx->cur++] - '0';
        if (neg) d = -d;
        x += s * d;
        s /= 10;
    } while (ctx->cur < ctx->len && is_digit(ctx->src[ctx->cur]));

    JSON *val = alloc(ctx->arena, sizeof(JSON), _Alignof(JSON));
    if (val == NULL)
        return NULL;
    val->type = JSON_TYPE_FLOAT;
    val->fval = x;

    return val;
}

static JSON *parse_int(Context *ctx)
{
    assert(ctx->cur < ctx->len && (is_digit(ctx->src[ctx->cur]) || ctx->src[ctx->cur] == '-'));

    bool neg = false;
    if (ctx->src[ctx->cur] == '-') {
        ctx->cur++;
        if (ctx->cur == ctx->len || !is_digit(ctx->src[ctx->cur]))
            return NULL;
        neg = true;
    }

    int64_t x = 0;
    do {
        int d = ctx->src[ctx->cur++] - '0';
        if (neg) {
            if (x < (INT64_MIN + d) / 10)
                return NULL;
            d = -d;
        } else {
            if (x > (INT64_MAX - d) / 10)
                return NULL;
        }
        x *= 10;
        x += d;
    } while (ctx->cur < ctx->len && is_digit(ctx->src[ctx->cur]));

    JSON *val = alloc(ctx->arena, sizeof(JSON), _Alignof(JSON));
    if (val == NULL)
        return NULL;
    val->type = JSON_TYPE_INT;
    val->ival = x;

    return val;
}

static bool follows_float(Context *ctx)
{
    assert(ctx->cur < ctx->len && (is_digit(ctx->src[ctx->cur]) || ctx->src[ctx->cur] == '-'));
    size_t peek = ctx->cur;

    if (peek < ctx->len && ctx->src[peek] == '-') {
        peek++;
        if (peek == ctx->len || !is_digit(ctx->src[peek]))
            return false;
    }

    do
        peek++;
    while (peek < ctx->len && is_digit(ctx->src[peek]));

    return peek < ctx->len && ctx->src[peek] == '.';
}

static JSON *parse_number(Context *ctx)
{
    if (follows_float(ctx))
        return parse_float(ctx);
    return parse_int(ctx);
}

static JSON *parse_true(Context *ctx)
{
    assert(ctx->cur < ctx->len && ctx->src[ctx->cur] == 't');
    ctx->cur++;

    if (ctx->len - ctx->cur <= 2
        || ctx->src[ctx->cur+0] != 'r'
        || ctx->src[ctx->cur+1] != 'u'
        || ctx->src[ctx->cur+2] != 'e')
        return NULL;
    ctx->cur += 3;

    JSON *val = alloc(ctx->arena, sizeof(JSON), _Alignof(JSON));
    if (val == NULL)
        return NULL;
    val->type = JSON_TYPE_BOOL;
    val->bval = true;

    return val;
}

static JSON *parse_false(Context *ctx)
{
    assert(ctx->cur < ctx->len && ctx->src[ctx->cur] == 'f');
    ctx->cur++;

    if (ctx->len - ctx->cur <= 3
        || ctx->src[ctx->cur+0] != 'a'
        || ctx->src[ctx->cur+1] != 'l'
        || ctx->src[ctx->cur+2] != 's'
        || ctx->src[ctx->cur+3] != 'e')
        return NULL;
    ctx->cur += 4;

    JSON *val = alloc(ctx->arena, sizeof(JSON), _Alignof(JSON));
    if (val == NULL)
        return NULL;
    val->type = JSON_TYPE_BOOL;
    val->bval = false;

    return val;
}

static JSON *parse_null(Context *ctx)
{
    assert(ctx->cur < ctx->len && ctx->src[ctx->cur] == 'n');
    ctx->cur++;

    if (ctx->len - ctx->cur <= 2
        || ctx->src[ctx->cur+0] != 'u'
        || ctx->src[ctx->cur+1] != 'l'
        || ctx->src[ctx->cur+2] != 'l')
        return NULL;
    ctx->cur += 3;

    JSON *val = alloc(ctx->arena, sizeof(JSON), _Alignof(JSON));
    if (val == NULL)
        return NULL;
    val->type = JSON_TYPE_NULL;

    return val;
}

static JSON *parse_any(Context *ctx)
{
    if (ctx->cur == ctx->len)
        return NULL;
    char c = ctx->src[ctx->cur];

    if (c == '"')
        return parse_string(ctx);

    if (c == '{')
        return parse_object(ctx);

    if (c == '[')
        return parse_array(ctx);

    if (is_digit(c) || c == '-')
        return parse_number(ctx);

    if (c == 't')
        return parse_true(ctx);

    if (c == 'f')
        return parse_false(ctx);

    if (c == 'n')
        return parse_null(ctx);

    return NULL;
}

static JSON *decode(Context *ctx)
{
    consume_wspace(ctx);

    JSON *x = parse_any(ctx);
    if (x == NULL)
        return NULL;
    x->key = NULL;
    x->key_len = 0;
    x->next = NULL;

    consume_wspace(ctx);

    if (ctx->cur < ctx->len)
        return NULL;

    return x;
}

JSON_Arena json_arena_init(char *ptr, size_t len)
{
    return (JSON_Arena) { NULL, ptr, len, 0 };
}

JSON *json_decode(char *src, int len, JSON_Arena *arena, JSON_Error *error)
{
    if (src == NULL) src = "";
    if (len < 0) len = strlen(src);

    Context ctx = { src, len, 0, arena, error };
    return decode(&ctx);
}

////////////////////////////////////////////////////////////////////
// UTILITIES
////////////////////////////////////////////////////////////////////

const char *json_type_name(JSON_Type type)
{
    switch (type) {
        case JSON_TYPE_BOOL  : return "bool";
        case JSON_TYPE_NULL  : return "null";
        case JSON_TYPE_OBJECT: return "object";
        case JSON_TYPE_ARRAY : return "array";
        case JSON_TYPE_FLOAT : return "float";
        case JSON_TYPE_INT   : return "int";
        case JSON_TYPE_STRING: return "string";
    }
    return "???";
}

JSON_Type json_get_type(JSON *json)
{
    assert(json);
    return json->type;
}

JSON_String json_get_key(JSON *json)
{
    if (json == NULL || json->key == NULL)
        return (JSON_String) { NULL, 0 };
    return (JSON_String) { json->key, json->key_len };
}

bool json_get_bool(JSON *json, bool fallback)
{
    if (json == NULL || json->type != JSON_TYPE_BOOL)
        return fallback;
    return json->bval;
}

int64_t json_get_int(JSON *json, int64_t fallback)
{
    if (json == NULL || json->type != JSON_TYPE_INT)
        return fallback;
    return json->ival;
}

double json_get_float(JSON *json, double fallback)
{
    if (json == NULL || json->type != JSON_TYPE_FLOAT)
        return fallback;
    return json->fval;
}

JSON_String json_get_string(JSON *json)
{
    if (json == NULL || json->type != JSON_TYPE_STRING)
        return (JSON_String) { NULL, 0 };
    return (JSON_String) { json->sval, json->len };
}

JSON *json_get_field(JSON *obj, JSON_String key)
{
    if (obj == NULL)
        return NULL;

    if (obj->type != JSON_TYPE_OBJECT)
        return NULL;

    JSON *child = obj->head;
    while (child) {
        if (child->key_len == (size_t) key.len &&
            !memcmp(child->key, key.ptr, key.len))
            return child;
        child = child->next;
    }

    return NULL;
}

////////////////////////////////////////////////////////////////////
// PATTERN MATCHING
////////////////////////////////////////////////////////////////////

typedef struct {
    char *src;
    int   len;
    int   cur;
    int   cur_arg;
    JSON_MatchArgs args;
    JSON_Error *err;
} MatchContext;

static int match_any(MatchContext *ctx, JSON *json);

static void report_match_error(MatchContext *ctx, char *fmt, ...)
{
    char *dst = ctx->err->msg;
    int   cap = (int) sizeof(ctx->err->msg);

    va_list args;
    va_start(args, fmt);
    int ret = vsnprintf(dst, cap, fmt, args);
    va_end(args);

    if (ret < 0)
        ret = 0;

    if (ret >= cap)
        ret = cap-1;

    dst[ret] = '\0';
}

static int match_obj(MatchContext *ctx, JSON *json)
{
    assert(json->type == JSON_TYPE_OBJECT);

    while (ctx->cur < ctx->len && is_wspace(ctx->src[ctx->cur]))
        ctx->cur++;

    if (ctx->cur == ctx->len) {
        report_match_error(ctx, "Pattern string ended inside an object");
        return -1;
    }

    // Empty object?
    if (ctx->cur < ctx->len && ctx->src[ctx->cur] == '}') {
        ctx->cur++;
        return 0;
    }

    for (;;) {

        assert(ctx->cur < ctx->len && !is_wspace(ctx->src[ctx->cur]));

        if (ctx->src[ctx->cur] != '\'') {
            report_match_error(ctx, "Invalid character inside object, where key was expected");
            return -1;
        }
        ctx->cur++;

        char key[128];
        int  key_len = 0;

        for (;;) {

            int off = ctx->cur;

            while (ctx->cur < ctx->len
                && ctx->src[ctx->cur] != '\''
                && ctx->src[ctx->cur] != '\\')
                ctx->cur++;

            char *substr_ptr = ctx->src + off;
            int   substr_len = ctx->cur - off;

            if (substr_len > 0) {
                if (sizeof(key) - key_len <= (size_t) substr_len) {
                    report_match_error(ctx, "Key buffer limit reached (you can't have keys longer than %d bytes)", (int) sizeof(key)-1);
                    return -1;
                }
                memcpy(key + key_len, substr_ptr, substr_len);
                key_len += substr_len;
            }

            if (ctx->cur == ctx->len) {
                report_match_error(ctx, "Pattern string ended inside a string");
                return -1;
            }

            if (ctx->src[ctx->cur] == '\'') {
                ctx->cur++;
                break;
            }

            assert(ctx->src[ctx->cur] == '\\');
            ctx->cur++;

            if (ctx->cur == ctx->len) {
                report_match_error(ctx, "Pattern string ended inside a string");
                return -1;
            }

            if (sizeof(key) - key_len <= 1) {
                report_match_error(ctx, "Key buffer limit reached (you can't have keys longer than %d bytes)", (int) sizeof(key)-1);
                return -1;
            }

            switch (ctx->src[ctx->cur]) {

                case '\'': key[key_len++] = '\''; break;
                case '\\': key[key_len++] = '\\'; break;

                default:
                report_match_error(ctx, "Invalid escape character");
                return -1;
            }
        }

        // Consume spaces to the next separator

        while (ctx->cur < ctx->len && is_wspace(ctx->src[ctx->cur]))
            ctx->cur++;

        if (ctx->cur == ctx->len || ctx->src[ctx->cur] != ':') {
            report_match_error(ctx, "Missing ':' after key");
            return -1;
        }
        ctx->cur++;

        // Look for a field with the given key in the object
        JSON *child = json->head;
        while (child) {
            if (child->key_len == (size_t) key_len &&
                !memcmp(child->key, key, key_len))
                break;
            child = child->next;
        }

        if (child == NULL) {
            report_match_error(ctx, "Field '%.*s' is missing", key_len, key);
            return 1;
        }

        int ret = match_any(ctx, child);
        if (ret < 0)
            return ret;

        while (ctx->cur < ctx->len && is_wspace(ctx->src[ctx->cur]))
            ctx->cur++;

        if (ctx->cur == ctx->len) {
            report_match_error(ctx, "Pattern string ended inside an object");
            return -1;
        }

        if (ctx->src[ctx->cur] == '}') {
            ctx->cur++;
            break;
        }

        if (ctx->src[ctx->cur] != ',') {
            report_match_error(ctx, "Invalid character where ',' or '}' were expected");
            return -1;
        }
        ctx->cur++;

        while (ctx->cur < ctx->len && is_wspace(ctx->src[ctx->cur]))
            ctx->cur++;

        if (ctx->cur == ctx->len) {
            report_match_error(ctx, "Pattern string ended inside an object");
            return -1;
        }
    }

    return 0;
}

static int match_any(MatchContext *ctx, JSON *json)
{
    while (ctx->cur < ctx->len && is_wspace(ctx->src[ctx->cur]))
        ctx->cur++;

    if (ctx->cur == ctx->len) {
        report_match_error(ctx, "Pattern string ended where a value was expected");
        return -1;
    }

    // The * character matches anything but doesn't extract any value
    if (ctx->src[ctx->cur] == '*') {
        ctx->cur++;
        return 0;
    }

    // The ? character matches anything and writes it to output
    if (ctx->src[ctx->cur] == '?') {
        ctx->cur++;

        if (ctx->cur_arg == ctx->args.len) {
            report_match_error(ctx, "Missing output arguments");
            return -1;
        }

        JSON_MatchArg arg = ctx->args.ptr[ctx->cur_arg++];
        switch (arg.type) {

            case JSON_MATCH_ARG_TYPE_BOOL:
            if (json->type != JSON_TYPE_BOOL) {
                report_match_error(ctx, "Expected boolean, got %s instead", json_type_name(json->type));
                return 1;
            }
            *arg.bptr = json->bval;
            break;

            case JSON_MATCH_ARG_TYPE_INT:
            if (json->type != JSON_TYPE_INT) {
                report_match_error(ctx, "Expected integer, got %s instead", json_type_name(json->type));
                return 1;
            }
            *arg.iptr = json->ival;
            break;

            case JSON_MATCH_ARG_TYPE_FLOAT:
            if (json->type != JSON_TYPE_FLOAT) {
                report_match_error(ctx, "Expected float, got %s instead", json_type_name(json->type));
                return 1;
            }
            *arg.fptr = json->fval;
            break;

            case JSON_MATCH_ARG_TYPE_STRING:
            if (json->type != JSON_TYPE_STRING) {
                report_match_error(ctx, "Expected string, got %s instead", json_type_name(json->type));
                return 1;
            }
            *arg.sptr = (JSON_String) { json->sval, json->len };
            break;

            case JSON_MATCH_ARG_TYPE_ANY:
            *arg.anyptr = json;
            break;
        }

        return 0;
    }

    if (ctx->src[ctx->cur] == '{') {
        ctx->cur++;

        if (json->type != JSON_TYPE_OBJECT) {
            report_match_error(ctx, "Expected object, got %s instead", json_type_name(json->type));
            return 1;
        }

        return match_obj(ctx, json);
    }

    char c = ctx->src[ctx->cur];
    if (c >= ' ' && c <= '~') report_match_error(ctx, "Unexpected character '%c' in pattern", c);
    else                      report_match_error(ctx, "Unexpected byte %x in pattern", c);

    return -1;
}

int json_match_impl(JSON *json, JSON_Error *err, char *pattern, JSON_MatchArgs args)
{
    MatchContext ctx = {
        .src     = pattern,
        .len     = strlen(pattern),
        .cur     = 0,
        .cur_arg = 0,
        .args    = args,
        .err     = err,
    };
    return match_any(&ctx, json);
}

JSON_MatchArg json_match_arg_bool  (bool        *x) { return (JSON_MatchArg) { .type=JSON_MATCH_ARG_TYPE_BOOL,   .bptr=x   }; }
JSON_MatchArg json_match_arg_int   (int64_t     *x) { return (JSON_MatchArg) { .type=JSON_MATCH_ARG_TYPE_INT,    .iptr=x   }; }
JSON_MatchArg json_match_arg_float (double      *x) { return (JSON_MatchArg) { .type=JSON_MATCH_ARG_TYPE_FLOAT,  .fptr=x   }; }
JSON_MatchArg json_match_arg_string(JSON_String *x) { return (JSON_MatchArg) { .type=JSON_MATCH_ARG_TYPE_STRING, .sptr=x   }; }
JSON_MatchArg json_match_arg_any   (JSON       **x) { return (JSON_MatchArg) { .type=JSON_MATCH_ARG_TYPE_ANY,    .anyptr=x }; }

////////////////////////////////////////////////////////////////////
// STRING ESCAPING
////////////////////////////////////////////////////////////////////

JSON_String json_escape(JSON_Arena *arena, JSON_String str)
{
    // TODO: This is just a best-effort implementation. Should handle UTF-8 precisely.

    char *src = str.ptr;
    int   len = str.len;
    int   cur = 0;

    char *dst = arena->ptr + arena->cur;
    int   cap = arena->len - arena->cur;
    int   num = 0;

    for (;;) {

        int off = cur;

        while (cur < len && (src[cur] >= ' ' && src[cur] <= '~' && src[cur] != '"' && src[cur] != '\\'))
            cur++;

        char *substr_ptr = src + off;
        int   substr_len = cur - off;

        if (substr_len > 0) {
            if (substr_len > cap - num)
                return (JSON_String) { NULL, 0 };
            memcpy(dst + num, substr_ptr, substr_len);
            num += substr_len;
        }

        if (cur == len)
            break;

        if (2 > cap - num)
            return (JSON_String) { NULL, 0 };

        cur++;
        if (src[cur-1] == '"') {
            dst[num++] = '\\';
            dst[num++] = '"';
        } else if (src[cur-1] == '\\') {
            dst[num++] = '\\';
            dst[num++] = '\\';
        } else if (src[cur-1] == '\n') {
            dst[num++] = '\\';
            dst[num++] = 'n';
        } else if (src[cur-1] == '\r') {
            dst[num++] = '\\';
            dst[num++] = 'r';
        } else if (src[cur-1] == '\t') {
            dst[num++] = '\\';
            dst[num++] = 't';
        } else {
            return (JSON_String) { NULL, 0 };
        }
    }

    arena->cur += num;
    return (JSON_String) { dst, num };
}
