#ifndef CONFIG_READER_INCLUDED
#define CONFIG_READER_INCLUDED

#include "lib/basic.h"

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
b8   config_reader_next(ConfigReader *reader, string *name, string *value);
void config_reader_rewind(ConfigReader *reader);

void parse_config_value_yn(string name, string value,
    b8 *out, b8 *bad_config);

void parse_config_value_port(string name, string value,
    u16 *out, b8 *bad_config);

#endif // CONFIG_READER_INCLUDED
