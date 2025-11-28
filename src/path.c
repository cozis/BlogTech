#include "path.h"

static int parse_path(HTTP_String path, HTTP_String *comps, int max)
{
    bool is_absolute = false;
    if (path.len > 0 && path.ptr[0] == '/') {
        is_absolute = true;
        path.ptr++;
        path.len--;
        if (path.len == 0)
            return 0; // Absolute paths with no components are allowed
    }

    int num = 0;
    uint32_t i = 0;
    for (;;) {

        uint32_t off = i;
        while (i < (uint32_t) path.len && path.ptr[i] != '/')
            i++;
        uint32_t len = i - off;

        if (len == 0)
            return -1; // Empty component

        HTTP_String comp = { path.ptr + off, len };
        if (comp.len == 2 && comp.ptr[0] == '.' && comp.ptr[1] == '.') {
            if (num == 0) {
                // For absolute paths, ".." at root is ignored (stays at root)
                // For relative paths, ".." with no components references parent, which is invalid
                if (!is_absolute)
                    return -1;
                // Otherwise, ignore the ".." (absolute path, already at root)
            } else {
                num--;
            }
        } else if (comp.len != 1 || comp.ptr[0] != '.') {
            if (num == max)
                return -1; // To many components
            comps[num++] = comp;
        }

        if (i == (uint32_t) path.len)
            break;

        assert(path.ptr[i] == '/');
        i++;

        if (i == (uint32_t) path.len)
            break;
    }

    return num;
}

#define MAX_COMPS 32

int translate_path(HTTP_String path,
    HTTP_String root, char *dst, int cap)
{
    int num_comps = 0;
    HTTP_String comps[MAX_COMPS];

    int ret = parse_path(root, comps + num_comps, MAX_COMPS - num_comps);
    if (ret < 0)
        return -1;
    num_comps += ret;

    ret = parse_path(path, comps + num_comps, MAX_COMPS - num_comps);
    if (ret < 0)
        return -1;
    num_comps += ret;

    int len = 0;
    if (root.len == 0 || root.ptr[0] != '/')
        len++;
    for (int i = 0; i < num_comps; i++)
        len += 1 + comps[i].len;
    if (len >= cap)
        return -1;

    int num = 0;
    if (root.len == 0 || root.ptr[0] != '/')
        dst[num++] = '.';
    for (int i = 0; i < num_comps; i++) {
        dst[num++] = '/';
        memcpy(dst + num, comps[i].ptr, comps[i].len);
        num += comps[i].len;
    }

    return num;
}
