// Fuzz harness for JSON parser
// Compile with:
//   clang -fsanitize=fuzzer,address -g fuzz_json.c -o fuzz_json
// Or for AFL:
//   afl-clang-fast fuzz_json.c -o fuzz_json_afl

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

// Include the JSON parser implementation
#define NDEBUG
#include "../src/lib/basic.c"
#include "../src/lib/json.c"

#define ARENA_SIZE (1024 * 64)

#ifdef __AFL_FUZZ_TESTCASE_LEN
// AFL++ persistent mode
__AFL_FUZZ_INIT();

int main(void)
{
    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(100000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;

        char arena_buf[ARENA_SIZE];
        JSON_Arena arena = json_arena_init(arena_buf, sizeof(arena_buf));
        JSON_Error error = {0};

        // Make a copy to ensure null-termination won't cause issues
        char *input = malloc(len + 1);
        if (!input) continue;
        memcpy(input, buf, len);
        input[len] = '\0';

        // Test json_decode
        JSON *result = json_decode(input, len, &arena, &error);

        // If parsing succeeded, test the accessor functions
        if (result) {
            JSON_Type type = json_get_type(result);
            (void)json_type_name(type);

            switch (type) {
                case JSON_TYPE_BOOL:
                    (void)json_get_bool(result, false);
                    break;
                case JSON_TYPE_INT:
                    (void)json_get_int(result, 0);
                    break;
                case JSON_TYPE_FLOAT:
                    (void)json_get_float(result, 0.0);
                    break;
                case JSON_TYPE_STRING:
                    (void)json_get_string(result);
                    break;
                case JSON_TYPE_OBJECT:
                    // Try to access some fields
                    (void)json_get_field(result, (JSON_String){"test", 4});
                    (void)json_get_field(result, (JSON_String){"", 0});
                    break;
                case JSON_TYPE_ARRAY:
                    // Iterate through array
                    for (JSON *child = result->head; child; child = child->next) {
                        (void)json_get_type(child);
                        (void)json_get_key(child);
                    }
                    break;
                case JSON_TYPE_NULL:
                    break;
            }
        }

        free(input);
    }

    return 0;
}

#else
// libFuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 1024 * 1024) {
        return 0;
    }

    char arena_buf[ARENA_SIZE];
    JSON_Arena arena = json_arena_init(arena_buf, sizeof(arena_buf));
    JSON_Error error = {0};

    // Make a mutable copy
    char *input = malloc(size + 1);
    if (!input) return 0;
    memcpy(input, data, size);
    input[size] = '\0';

    // Test json_decode with explicit length
    JSON *result = json_decode(input, (int)size, &arena, &error);

    // If parsing succeeded, exercise the accessor functions
    if (result) {
        JSON_Type type = json_get_type(result);
        (void)json_type_name(type);

        switch (type) {
            case JSON_TYPE_BOOL:
                (void)json_get_bool(result, false);
                break;
            case JSON_TYPE_INT:
                (void)json_get_int(result, 0);
                break;
            case JSON_TYPE_FLOAT:
                (void)json_get_float(result, 0.0);
                break;
            case JSON_TYPE_STRING:
                (void)json_get_string(result);
                break;
            case JSON_TYPE_OBJECT:
                // Try accessing fields
                (void)json_get_field(result, (JSON_String){"test", 4});
                (void)json_get_field(result, (JSON_String){"", 0});
                // Iterate children
                for (JSON *child = result->head; child; child = child->next) {
                    (void)json_get_type(child);
                    (void)json_get_key(child);
                }
                break;
            case JSON_TYPE_ARRAY:
                // Iterate through array
                for (JSON *child = result->head; child; child = child->next) {
                    (void)json_get_type(child);
                }
                break;
            case JSON_TYPE_NULL:
                break;
        }
    }

    // Also test json_decode with len=-1 (auto-detect)
    arena = json_arena_init(arena_buf, sizeof(arena_buf));
    result = json_decode(input, -1, &arena, &error);

    free(input);
    return 0;
}
#endif

// Standalone mode for manual testing
#ifdef STANDALONE
int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = malloc(size);
    if (!data) {
        fclose(f);
        return 1;
    }

    fread(data, 1, size, f);
    fclose(f);

    int result = LLVMFuzzerTestOneInput(data, size);
    free(data);

    printf("Test completed\n");
    return result;
}
#endif
