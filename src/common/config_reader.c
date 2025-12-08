#include "file_system.h"
#include "config_reader.h"

#ifndef DEFAULT_CONFIG_FILE
#define DEFAULT_CONFIG_FILE "blogtech.conf"
#endif

static int read_config_file(int argc, char **argv, HTTP_String *text)
{
    bool no_config = false;
    HTTP_String file = { NULL, 0 };
    for (int i = 1; i < argc; i++) {

        if (!strcmp(argv[i], "--config")) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing path after --config\n");
                return -1;
            }
            no_config = false;
            file = (HTTP_String) { argv[i], strlen(argv[i]) };
            break;
        }

        if (!strcmp(argv[i], "--no-config")) {
            no_config = true;
            file = (HTTP_String) { NULL, 0 };
            break;
        }
    }

    if (!no_config && file.len == 0)
        if (file_exists(HTTP_STR(DEFAULT_CONFIG_FILE)))
            file = HTTP_STR(DEFAULT_CONFIG_FILE);

    if (file.len == 0)
        *text = (HTTP_String) { NULL, 0 };
    else {
        int ret = file_read_all(file, text);
        if (ret < 0) {
            printf("Couldn't load file");
            return -1;
        }
    }

    return 0;
}

static bool is_white_space(char c)
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

    assert(reader->cur == reader->len || !is_white_space(reader->src[reader->cur]));
}

int config_reader_init(ConfigReader *reader, int argc, char **argv)
{
    HTTP_String text;
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
    HTTP_String *name, HTTP_String *value)
{
    // Either the source ended or we found something
    // that is not white space.
    assert(reader->cur == reader->len || !is_white_space(reader->src[reader->cur]));

    if (reader->cur == reader->len)
        return 0; // Source ended

    int off = reader->cur;
    while (reader->cur < reader->len && !is_white_space(reader->src[reader->cur]))
        reader->cur++;

    *name = (HTTP_String) {
        reader->src + off,
        reader->cur - off
    };

    while (reader->cur < reader->len && (reader->src[reader->cur] == ' ' || reader->src[reader->cur] == '\t'))
        reader->cur++;

    if (reader->cur == reader->len
        || reader->src[reader->cur] == '\n'
        || reader->src[reader->cur] == '\r'
        || reader->src[reader->cur] == '#') {
        *value = (HTTP_String) { NULL, 0 };
    } else {

        off = reader->cur;
        while (reader->cur < reader->len
            && reader->src[reader->cur] != '\r'
            && reader->src[reader->cur] != '\n'
            && reader->src[reader->cur] != '#')
            reader->cur++;

        *value = (HTTP_String) {
            reader->src + off,
            reader->cur - off
        };

        if (http_streq(*value, HTTP_STR("---")))
            *value = (HTTP_String) { NULL, 0 };
    }

    consume_whitespace_and_comments(reader);
    return 1;
}

static int read_value_from_cmdline(ConfigReader *reader,
    HTTP_String *name, HTTP_String *value)
{
    if (reader->argidx == reader->argc)
        return 0;

    char *src = reader->argv[reader->argidx++];
    int   len = strlen(src);
    int   cur = 0;

    if (cur == len) {
        printf("Config Warning: Option is empty\n");
        return -1;
    }

    if (src[cur] != '-') {
        // Unnamed option
        *name = (HTTP_String) { NULL, 0 };
        *value = (HTTP_String) { src, len };
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

    *name = (HTTP_String) { src + off, cur - off };

    if (cur == len) {
        *value = (HTTP_String) { NULL, 0 };
    } else {
        cur++;
        *value = (HTTP_String) { src + cur, len - cur };
    }

    return 1;
}

bool config_reader_next(ConfigReader *reader, HTTP_String *name, HTTP_String *value)
{
    int ret;
    do {
        ret = read_value_from_file(reader, name, value);
        if (ret == 0)
            ret = read_value_from_cmdline(reader, name, value);

        // Never return options that were consumed by the reader itself
        if (ret == 1) {
            if (http_streq(*name, HTTP_STR("config")) || http_streq(*name, HTTP_STR("no-config")))
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

void parse_config_value_yn(HTTP_String name, HTTP_String value,
    bool *out, bool *bad_config)
{
    if (http_streq(value, HTTP_STR("yes")) || http_streq(value, HTTP_STR(""))) {
        *out = true;
    } else if (http_streq(value, HTTP_STR("no"))) {
        *out = false;
    } else {
        printf("Config Error: Unexpected value '%.*s' for option '%.*s' ('yes', 'no', or '' were expected)\n",
            HTTP_UNPACK(value),
            HTTP_UNPACK(name));
        *bad_config = true;
    }
}

static bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

void parse_config_value_port(HTTP_String name, HTTP_String value,
    uint16_t *out, bool *bad_config)
{
    char *src = value.ptr;
    int   len = value.len;
    int   cur = 0;

    if (cur == len || !is_digit(src[cur])) {
        printf("Config Error: Option '%.*s' is not a valid port number\n",
            HTTP_UNPACK(name));
        *bad_config = true;
        return;
    }

    uint16_t buf = src[cur] - '0';
    cur++;

    while (cur < len && is_digit(src[cur])) {
        int d = src[cur] - '0';
        cur++;
        if (buf > (UINT16_MAX - d) / 10) {
            printf("Config Error: Option '%.*s' is not a valid port number (must be in range [0, 65535])\n",
                HTTP_UNPACK(name));
            *bad_config = true;
            return;
        }
        buf = buf * 10 + d;
    }

    if (cur < len) {
        printf("Config Error: Option '%.*s' is not a valid port number\n",
            HTTP_UNPACK(name));
        *bad_config = true;
        return;
    }

    *out = buf;
}
