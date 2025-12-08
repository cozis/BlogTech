#ifndef CONFIG_READER_INCLUDED
#define CONFIG_READER_INCLUDED

#include <stdbool.h>
#include "chttp.h" // Only needed for HTTP_String

typedef struct {
    char  *src;
    int    len;
    int    cur;
    int    argc;
    char **argv;
    int    argidx;
} ConfigReader;

int  config_reader_init(ConfigReader *reader, int argc, char **argv);
void config_reader_free(ConfigReader *reader);
bool config_reader_next(ConfigReader *reader, HTTP_String *name, HTTP_String *value);
void config_reader_rewind(ConfigReader *reader);

void parse_config_value_yn(HTTP_String name, HTTP_String value,
    bool *out, bool *bad_config);

void parse_config_value_port(HTTP_String name, HTTP_String value,
    uint16_t *out, bool *bad_config);

#endif // CONFIG_READER_INCLUDED
