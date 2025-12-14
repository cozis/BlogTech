#include <stdio.h>
#include <stdlib.h>

#include "config_reader.h"

#include "lib/file_system.h"

#ifndef DEFAULT_CONFIG_FILE
#define DEFAULT_CONFIG_FILE "blogtech.conf"
#endif

static b8 startswith(string str, string pre)
{
    if (str.len < pre.len)
        return false;
    str.len = pre.len;
    return streq(str, pre);
}

static int read_config_file(int argc, char **argv, string *text)
{
    b8 no_config = false;
    string file = EMPTY_STRING;
    for (int i = 1; i < argc; i++) {

        string arg = ZT2S(argv[i]);

        // TODO: this should use the regular argument parser, not do an ad-hoc thing
        if (startswith(arg, S("--config="))) {
            file = arg;
            file.ptr += S("--config=").len;
            file.len -= S("--config=").len;
            no_config = false;
            break;
        }

        if (streq(arg, S("--no-config"))) {
            no_config = true;
            file = EMPTY_STRING;
            break;
        }
    }

    if (!no_config && file.len == 0) {
        int ret = file_exists(S(DEFAULT_CONFIG_FILE));
        if (ret < 0) {
            if (ret != FS_ERROR_NOTFOUND)
                return -1;
            file = S(DEFAULT_CONFIG_FILE);
        }
    }

    if (file.len == 0)
        *text = EMPTY_STRING;
    else {
        int ret = file_read_all(file, text);
        if (ret < 0) {
            if (ret != FS_ERROR_NOTFOUND) {
                printf("Couldn't load file");
                return -1;
            }
            *text = EMPTY_STRING;
        }
    }

    return 0;
}

static b8 is_white_space(char c)
{
    return c == ' '
        || c == '\t'
        || c == '\r'
        || c == '\n';
}

static void
consume_whitespace_and_comments(ConfigReader *reader)
{
    for (;;) {

        while (reader->cur < reader->len && is_white_space(reader->src[reader->cur]))
            reader->cur++;

        if (reader->cur == reader->len || reader->src[reader->cur] != '#')
            break;

        while (reader->cur < reader->len && reader->src[reader->cur] != '\n')
            reader->cur++;
    }

    ASSERT(reader->cur == reader->len || !is_white_space(reader->src[reader->cur]));
}

int config_reader_init(ConfigReader *reader, int argc, char **argv)
{
    string text;
    int ret = read_config_file(argc, argv, &text);
    if (ret < 0)
        return -1;
    reader->src = text.ptr;
    reader->len = text.len;
    reader->cur = 0;
    reader->argc = argc;
    reader->argv = argv;
    reader->argidx = 1;
    consume_whitespace_and_comments(reader);
    return 0;
}

void config_reader_free(ConfigReader *reader)
{
    free(reader->src);
}

static int read_value_from_file(ConfigReader *reader,
    string *name, string *value)
{
    // Either the source ended or we found something
    // that is not white space.
    ASSERT(reader->cur == reader->len || !is_white_space(reader->src[reader->cur]));

    if (reader->cur == reader->len)
        return 0; // Source ended

    int off = reader->cur;
    while (reader->cur < reader->len && !is_white_space(reader->src[reader->cur]))
        reader->cur++;

    *name = (string) {
        reader->src + off,
        reader->cur - off
    };

    while (reader->cur < reader->len && (reader->src[reader->cur] == ' ' || reader->src[reader->cur] == '\t'))
        reader->cur++;

    if (reader->cur == reader->len
        || reader->src[reader->cur] == '\n'
        || reader->src[reader->cur] == '\r'
        || reader->src[reader->cur] == '#') {
        *value = EMPTY_STRING;
    } else {

        off = reader->cur;
        while (reader->cur < reader->len
            && reader->src[reader->cur] != '\r'
            && reader->src[reader->cur] != '\n'
            && reader->src[reader->cur] != '#')
            reader->cur++;

        *value = (string) {
            reader->src + off,
            reader->cur - off
        };

        if (streq(*value, S("---")))
            *value = EMPTY_STRING;
    }

    consume_whitespace_and_comments(reader);
    return 1;
}

static int read_value_from_cmdline(ConfigReader *reader,
    string *name, string *value)
{
    if (reader->argidx == reader->argc)
        return 0;

    string arg = ZT2S(reader->argv[reader->argidx]);
    reader->argidx++;

    char *src = arg.ptr;
    int   len = arg.len;
    int   cur = 0;

    if (cur == len) {
        printf("Config Warning: Option is empty\n");
        return -1;
    }

    if (src[cur] != '-') {
        // Unnamed option
        *name = EMPTY_STRING;
        *value = (string) { src, len };
        return 1;
    }
    cur++;

    if (cur < len && src[cur] == '-') {
        cur++; // Consume the dash

        // Argument starts with "--" (two dashes)
        if (cur == len) {
            printf("Config Warning: In option '%.*s', the name is missing after '--'\n", len, src);
            return -1;
        }
        if (src[cur] == '-') {
            printf("Config Warning: In option '%.*s', only two dashes were expected before the name\n", len, src);
            return -1;
        }
    }

    if (cur == len || src[cur] == '=') {
        printf("Config Warning: In option '%.*s', the name is missing after '%.*s'\n", len, src, cur, src);
        return -1;
    }

    int off = cur;
    do
        cur++;
    while (cur < len && src[cur] != '=');

    *name = (string) { src + off, cur - off };

    if (cur == len) {
        *value = EMPTY_STRING;
    } else {
        cur++;
        *value = (string) { src + cur, len - cur };
    }

    return 1;
}

b8 config_reader_next(ConfigReader *reader, string *name, string *value)
{
    int ret;
    do {
        ret = read_value_from_file(reader, name, value);
        if (ret == 0)
            ret = read_value_from_cmdline(reader, name, value);

        // Never return options that were consumed by the reader itself
        if (ret == 1) {
            if (streq(*name, S("config")) || streq(*name, S("no-config")))
                ret = -1;
        }

    } while (ret < 0);
    return ret != 0 ? true : false;
}

void config_reader_rewind(ConfigReader *reader)
{
    reader->cur = 0;
    reader->argidx = 1;
    consume_whitespace_and_comments(reader);
}

void parse_config_value_yn(string name, string value,
    b8 *out, b8 *bad_config)
{
    if (streq(value, S("yes")) || streq(value, EMPTY_STRING)) {
        *out = true;
    } else if (streq(value, S("no"))) {
        *out = false;
    } else {
        printf("Config Error: Unexpected value '%.*s' for option '%.*s' ('yes', 'no', or '' were expected)\n",
            UNPACK(value),
            UNPACK(name));
        *bad_config = true;
    }
}

static b8 is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static int parse_u64(char *src, int len, u64 *out)
{
    int cur = 0;

    if (cur == len || !is_digit(src[cur]))
        return -1;

    u64 buf = src[cur] - '0';
    cur++;

    while (cur < len && is_digit(src[cur])) {
        int d = src[cur] - '0';
        cur++;
        if (buf > (U64_MAX - d) / 10)
            return -1;
        buf = buf * 10 + d;
    }

    if (cur < len)
        return -1;

    *out = buf;
    return 0;
}

void parse_config_value_port(string name, string value,
    u16 *out, b8 *bad_config)
{
    u64 tmp;
    if (parse_u64(value.ptr, value.len, &tmp) < 0 || tmp > U16_MAX) {
        printf("Config Error: Option '%.*s' is not a valid port number\n",
            UNPACK(name));
        *bad_config = true;
        return;
    }
    *out = (u16) tmp;
}

void parse_config_value_time_ms(string name, string value, s32 *out, b8 *bad_config)
{
    u64 tmp;
    if (parse_u64(value.ptr, value.len, &tmp) < 0 || tmp > S32_MAX) {
        printf("Config Error: Option '%.*s' is not a valid time interval in milliseconds\n",
            UNPACK(name));
        *bad_config = true;
        return;
    }
    *out = (s32) tmp;
}

void parse_config_value_buffer_size(string name, string value, s32 *out, b8 *bad_config)
{
    u64 tmp;
    if (parse_u64(value.ptr, value.len, &tmp) < 0 || tmp > S32_MAX) {
        printf("Config Error: Option '%.*s' is not a valid buffer size in bytes\n",
            UNPACK(name));
        *bad_config = true;
        return;
    }
    *out = (s32) tmp;
}

void parse_config_extra_cert(string name, string value,
    string *extra_domain, string *extra_cert_file,
    string *extra_cert_key_file, b8 *bad_config)
{
    char *src = value.ptr;
    int   len = value.len;
    int   cur = 0;
    int   off;

    // Skip spaces before the first value
    while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
        cur++;

    off = cur;

    // Skip until a space or the separator
    while (cur < len && src[cur] != ',' && src[cur] != ' ' && src[cur] != '\t')
        cur++;

    // Skip spaces before the separator
    while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
        cur++;

    if (cur == len) {
        printf("Config Error: Option '%.*s' is not a valid domain-certificate-key triplet separated by a commas\n", UNPACK(name));
        *bad_config = true;
        return;
    }

    *extra_domain = (string) { src + off, cur - off };

    // Consume separator
    ASSERT(src[cur] == ',');
    cur++;

    // Skip spaces after the separator
    while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
        cur++;

    off = cur;

    // Find the second separator
    while (cur < len && src[cur] != ',' && src[cur] != ' ' && src[cur] != '\t')
        cur++;

    *extra_cert_file = (string) { src + off, cur - off };

    // Skip spaces before the second separator
    while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
        cur++;

    if (cur == len) {
        printf("Config Error: Option '%.*s' is not a valid domain-certificate-key triplet separated by a commas\n",
            UNPACK(name));
        *bad_config = true;
        return;
    }

    ASSERT(src[cur] == ',');
    cur++;

    // Skip spaces after the separator
    while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
        cur++;

    off = cur;

    // Find the second separator
    while (cur < len && src[cur] != ',' && src[cur] != ' ' && src[cur] != '\t')
        cur++;

    *extra_cert_key_file = (string) { src + off, cur - off };

    // Skip spaces after the separator
    while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
        cur++;

    if (cur != len) {
        printf("Config Error: Option '%.*s' is not a valid domain-certificate-key triplet separated by a commas\n",
            UNPACK(name));
        *bad_config = true;
        return;
    }
}