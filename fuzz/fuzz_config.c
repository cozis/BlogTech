// Fuzz harness for config file parser
// Compile with:
//   clang -fsanitize=fuzzer,address -g fuzz_config.c -o fuzz_config
// Or for AFL:
//   afl-clang-fast fuzz_config.c -o fuzz_config_afl

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#define NDEBUG
#include "../src/lib/basic.h"
#include "../src/lib/basic.c"

// Simplified config reader for fuzzing
// This tests the core parsing logic without file I/O

typedef struct {
    char *src;
    int   len;
    int   cur;
    int   argc;
    char **argv;
    int   argidx;
} ConfigReader;

static b8 is_white_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static void consume_whitespace_and_comments(ConfigReader *reader)
{
    for (;;) {
        while (reader->cur < reader->len && is_white_space(reader->src[reader->cur]))
            reader->cur++;
        if (reader->cur == reader->len || reader->src[reader->cur] != '#')
            break;
        while (reader->cur < reader->len && reader->src[reader->cur] != '\n')
            reader->cur++;
    }
}

static int read_value_from_file(ConfigReader *reader, string *name, string *value)
{
    if (reader->cur == reader->len)
        return 0;

    int off = reader->cur;
    while (reader->cur < reader->len && !is_white_space(reader->src[reader->cur]))
        reader->cur++;

    *name = (string) { reader->src + off, reader->cur - off };

    while (reader->cur < reader->len && (reader->src[reader->cur] == ' ' || reader->src[reader->cur] == '\t'))
        reader->cur++;

    if (reader->cur == reader->len ||
        reader->src[reader->cur] == '\n' ||
        reader->src[reader->cur] == '\r' ||
        reader->src[reader->cur] == '#') {
        *value = EMPTY_STRING;
    } else {
        off = reader->cur;
        while (reader->cur < reader->len &&
               reader->src[reader->cur] != '\r' &&
               reader->src[reader->cur] != '\n' &&
               reader->src[reader->cur] != '#')
            reader->cur++;
        *value = (string) { reader->src + off, reader->cur - off };
        if (streq(*value, S("---")))
            *value = EMPTY_STRING;
    }

    consume_whitespace_and_comments(reader);
    return 1;
}

static b8 config_reader_next(ConfigReader *reader, string *name, string *value)
{
    int ret = read_value_from_file(reader, name, value);
    return ret != 0 ? true : false;
}

static void config_reader_rewind(ConfigReader *reader)
{
    reader->cur = 0;
    consume_whitespace_and_comments(reader);
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

static void parse_config_value_yn(string name, string value, b8 *out, b8 *bad_config)
{
    if (streq(value, S("yes")) || streq(value, EMPTY_STRING)) {
        *out = true;
    } else if (streq(value, S("no"))) {
        *out = false;
    } else {
        *bad_config = true;
    }
}

static void parse_config_value_port(string name, string value, u16 *out, b8 *bad_config)
{
    u64 tmp;
    if (parse_u64(value.ptr, value.len, &tmp) < 0 || tmp > U16_MAX) {
        *bad_config = true;
        return;
    }
    *out = (u16) tmp;
}

static void parse_config_value_time_ms(string name, string value, s32 *out, b8 *bad_config)
{
    u64 tmp;
    if (parse_u64(value.ptr, value.len, &tmp) < 0 || tmp > S32_MAX) {
        *bad_config = true;
        return;
    }
    *out = (s32) tmp;
}

static void parse_config_value_buffer_size(string name, string value, s32 *out, b8 *bad_config)
{
    u64 tmp;
    if (parse_u64(value.ptr, value.len, &tmp) < 0 || tmp > S32_MAX) {
        *bad_config = true;
        return;
    }
    *out = (s32) tmp;
}

static void parse_config_extra_cert(string name, string value,
    string *extra_domain, string *extra_cert_file,
    string *extra_cert_key_file, b8 *bad_config)
{
    char *src = value.ptr;
    int   len = value.len;
    int   cur = 0;
    int   off;

    while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
        cur++;

    off = cur;
    while (cur < len && src[cur] != ',' && src[cur] != ' ' && src[cur] != '\t')
        cur++;

    while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
        cur++;

    if (cur == len) {
        *bad_config = true;
        return;
    }

    *extra_domain = (string) { src + off, cur - off };

    if (src[cur] != ',') {
        *bad_config = true;
        return;
    }
    cur++;

    while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
        cur++;

    off = cur;
    while (cur < len && src[cur] != ',' && src[cur] != ' ' && src[cur] != '\t')
        cur++;

    *extra_cert_file = (string) { src + off, cur - off };

    while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
        cur++;

    if (cur == len) {
        *bad_config = true;
        return;
    }

    if (src[cur] != ',') {
        *bad_config = true;
        return;
    }
    cur++;

    while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
        cur++;

    off = cur;
    while (cur < len && src[cur] != ',' && src[cur] != ' ' && src[cur] != '\t')
        cur++;

    *extra_cert_key_file = (string) { src + off, cur - off };

    while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
        cur++;

    if (cur != len) {
        *bad_config = true;
        return;
    }
}

#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();

int main(void)
{
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(100000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;

        char *input = malloc(len + 1);
        if (!input) continue;
        memcpy(input, buf, len);
        input[len] = '\0';

        ConfigReader reader = {
            .src = input,
            .len = len,
            .cur = 0,
            .argc = 0,
            .argv = NULL,
            .argidx = 0,
        };

        consume_whitespace_and_comments(&reader);

        string name, value;
        b8 bad_config = false;

        while (config_reader_next(&reader, &name, &value)) {
            // Test various parsing functions
            b8 yn_result = false;
            parse_config_value_yn(name, value, &yn_result, &bad_config);

            u16 port_result = 0;
            parse_config_value_port(name, value, &port_result, &bad_config);

            s32 time_result = 0;
            parse_config_value_time_ms(name, value, &time_result, &bad_config);

            s32 buffer_result = 0;
            parse_config_value_buffer_size(name, value, &buffer_result, &bad_config);

            string domain, cert, key;
            parse_config_extra_cert(name, value, &domain, &cert, &key, &bad_config);
        }

        // Test rewind
        config_reader_rewind(&reader);

        // Read again
        while (config_reader_next(&reader, &name, &value)) {
            (void)name;
            (void)value;
        }

        free(input);
    }
    return 0;
}

#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 1024 * 1024) return 0;

    char *input = malloc(size + 1);
    if (!input) return 0;
    memcpy(input, data, size);
    input[size] = '\0';

    ConfigReader reader = {
        .src = input,
        .len = (int)size,
        .cur = 0,
        .argc = 0,
        .argv = NULL,
        .argidx = 0,
    };

    consume_whitespace_and_comments(&reader);

    string name, value;
    b8 bad_config = false;

    while (config_reader_next(&reader, &name, &value)) {
        // Test various parsing functions with the parsed name/value pairs
        b8 yn_result = false;
        parse_config_value_yn(name, value, &yn_result, &bad_config);

        u16 port_result = 0;
        parse_config_value_port(name, value, &port_result, &bad_config);

        s32 time_result = 0;
        parse_config_value_time_ms(name, value, &time_result, &bad_config);

        s32 buffer_result = 0;
        parse_config_value_buffer_size(name, value, &buffer_result, &bad_config);

        // Test extra cert parsing
        string domain = EMPTY_STRING, cert = EMPTY_STRING, key = EMPTY_STRING;
        parse_config_extra_cert(name, value, &domain, &cert, &key, &bad_config);
    }

    // Test rewind functionality
    config_reader_rewind(&reader);

    // Read all entries again
    while (config_reader_next(&reader, &name, &value)) {
        (void)name;
        (void)value;
    }

    free(input);
    return 0;
}
#endif

#ifdef STANDALONE
int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *data = malloc(size);
    if (!data) { fclose(f); return 1; }
    fread(data, 1, size, f);
    fclose(f);
    int result = LLVMFuzzerTestOneInput(data, size);
    free(data);
    printf("Test completed\n");
    return result;
}
#endif
