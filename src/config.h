#ifndef CONFIG_INCLUDED
#define CONFIG_INCLUDED

#include <stdint.h>
#include <stdbool.h>
#include "chttp.h"

typedef enum {
    CONFIG_TARGET_TYPE_STR,
    CONFIG_TARGET_TYPE_U16,
    CONFIG_TARGET_TYPE_BOOL,
} ConfigTargetType;

typedef struct {
    ConfigTargetType type;
    HTTP_String      name;
    int *num;
    int cap;
    bool set;
    bool optional;
    union {
        HTTP_String *val_str;
        uint16_t    *val_u16;
        bool        *val_bool;
    };
    union {
        HTTP_String def_str;
        uint16_t    def_u16;
        bool        def_bool;
    };
} ConfigTarget;

#define CONFIG_TARGET_STR(name_, ptr, cap_, num_)  (ConfigTarget) { .type=CONFIG_TARGET_TYPE_STR,  .name=HTTP_STR(name_), .val_str=(ptr),  .num=(num_), .cap=(cap_), .set=false, .optional=false }
#define CONFIG_TARGET_U16(name_, ptr, cap_, num_)  (ConfigTarget) { .type=CONFIG_TARGET_TYPE_U16,  .name=HTTP_STR(name_), .val_u16=(ptr),  .num=(num_), .cap=(cap_), .set=false, .optional=false }
#define CONFIG_TARGET_BOOL(name_, ptr, cap_, num_) (ConfigTarget) { .type=CONFIG_TARGET_TYPE_BOOL, .name=HTTP_STR(name_), .val_bool=(ptr), .num=(num_), .cap=(cap_), .set=false, .optional=false }

#define CONFIG_TARGET_STR_OPT(name_, ptr, cap_, num_, def)  (ConfigTarget) { .type=CONFIG_TARGET_TYPE_STR,  .name=HTTP_STR(name_), .val_str=(ptr),  .def_str=(def),  .num=(num_), .cap=(cap_), .set=false, .optional=true }
#define CONFIG_TARGET_U16_OPT(name_, ptr, cap_, num_, def)  (ConfigTarget) { .type=CONFIG_TARGET_TYPE_U16,  .name=HTTP_STR(name_), .val_u16=(ptr),  .def_u16=(def),  .num=(num_), .cap=(cap_), .set=false, .optional=true }
#define CONFIG_TARGET_BOOL_OPT(name_, ptr, cap_, num_, def) (ConfigTarget) { .type=CONFIG_TARGET_TYPE_BOOL, .name=HTTP_STR(name_), .val_bool=(ptr), .def_bool=(def), .num=(num_), .cap=(cap_), .set=false, .optional=true }

void config_load(ConfigTarget *targets, int num_targets, char *src, int len, int argc, char **argv);

#endif // CONFIG_INCLUDED
