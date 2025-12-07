#include <assert.h>
#include <stdint.h>
#include "config.h"

static bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static void store_into_target(ConfigTarget *targets, int num_targets,
    HTTP_String name, HTTP_String value)
{
    for (int i = 0; i < num_targets; i++) {

        if (!http_streq(targets[i].name, name))
            continue;

        int idx = targets[i].num ? *targets[i].num : 0;
        if (idx == targets[i].cap)
            continue;

        switch (targets[i].type) {
        case CONFIG_TARGET_TYPE_STR:
            targets[i].val_str[idx] = value;
            break;
        case CONFIG_TARGET_TYPE_U16:
            {
                int cur = 0;
                if (cur == value.len || !is_digit(value.ptr[cur])) {
                    assert(0); // TODO
                }

                uint16_t buf = value.ptr[cur] - '0';
                cur++;

                while (cur < value.len) {

                    if (!is_digit(value.ptr[cur])) {
                        assert(0); // TODO
                    }

                    int d = value.ptr[cur] - '0';
                    cur++;

                    if (buf > (UINT16_MAX - d) / 10) {
                        assert(0); // TODO
                    }
                    buf = buf * 10 + d;
                }

                targets[i].val_u16[idx] = buf;
            }
            break;
        case CONFIG_TARGET_TYPE_BOOL:
            {
                bool buf;
                if (http_streq(value, HTTP_STR("yes"))) {
                    buf = true;
                } else if (http_streq(value, HTTP_STR("no"))) {
                    buf = false;
                } else {
                    assert(0); // TODO
                }
                targets[i].val_bool[idx] = buf;
            }
            break;
        }
        if (targets[i].num)
            (*targets[i].num)++;
        targets[i].set = true;
    }
}

static bool is_white_space(char c)
{
    return c == ' '
        || c == '\t'
        || c == '\n'
        || c == '\r';
}

void config_load(ConfigTarget *targets, int num_targets, char *src, int len, int argc, char **argv)
{
    int cur = 0;
    for (;;) {

        // Consume white space and comments
        for (;;) {

            while (cur < len && is_white_space(src[cur]))
                cur++;

            if (cur == len || src[cur] != '#')
                break;

            while (cur < len && src[cur] != '\n')
                cur++;
        };

        // Either the source ended or we found something
        // that is not white space.
        assert(cur == len || !is_white_space(src[cur]));
        if (cur == len) break;

        int off = cur;
        while (cur < len && !is_white_space(src[cur]))
            cur++;

        HTTP_String name = { src + off, cur - off };

        while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
            cur++;

        HTTP_String value;
        if (cur == len || src[cur] == '\n' || src[cur] == '\r' || src[cur] == '#') {
            value = (HTTP_String) { NULL, 0 };
        } else {
            off = cur;
            while (cur < len && src[cur] != '\r' && src[cur] != '\n' && src[cur] != '#')
                cur++;
            value = (HTTP_String) { src + off, cur - off };

            if (value.len == 3
                && value.ptr[0] == '-'
                && value.ptr[1] == '-'
                && value.ptr[2] == '-')
                value = (HTTP_String) { NULL, 0 };
        }

        store_into_target(targets, num_targets, name, value);
    }

    for (int i = 1; i < argc; i++) {

        char *src = argv[i];
        int   len = strlen(src);

        int cur = 0;
        while (cur < len && src[cur] == '-')
            cur++;

        int off = cur;
        while (cur < len && src[cur] != '=')
            cur++;
        HTTP_String name = { src + off, cur - off };

        HTTP_String value = { NULL, 0 };
        if (cur < len && src[cur] == '=') {
            cur++;
            value = (HTTP_String) { src + cur, len - cur };
        }

        store_into_target(targets, num_targets, name, value);
    }

    bool all_set = true;
    for (int i = 0; i < num_targets; i++) {
        if (!targets[i].set) {
            if (targets[i].optional) {
                switch (targets[i].type) {
                case CONFIG_TARGET_TYPE_STR:
                    *targets[i].val_str = targets[i].def_str;
                    break;
                case CONFIG_TARGET_TYPE_U16:
                    *targets[i].val_u16 = targets[i].def_u16;
                    break;
                case CONFIG_TARGET_TYPE_BOOL:
                    *targets[i].val_bool = targets[i].def_bool;
                    break;
                }
            } else {
                printf("Missing option '%.*s'\n", HTTP_UNPACK(targets[i].name));
                all_set = false;
            }
        }
    }

    if (!all_set) {
        exit(-1); // TODO
    }
}
