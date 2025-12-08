#ifndef PATH_INCLUDED
#define PATH_INCLUDED

#include "../common/chttp.h"

int translate_path(HTTP_String path,
    HTTP_String root, char *dst, int cap);

#endif // PATH_INCLUDED
