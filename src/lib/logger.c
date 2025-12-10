#include <stdlib.h> // malloc, free
#include "logger.h"
#include "string_builder.h"

int logger_init(Logger *l, int cap, int timeout, string path)
{
    l->buf = malloc(cap);
    if (l->buf == NULL)
        return -1;
    l->len = 0;
    l->cap = cap;

    if (file_open(path, &l->fd, FILE_OPEN_WRITE) < 0)
        return -1;

    l->timeout = timeout;
    l->last_flush = INVALID_TIME;
    return 0;
}

void logger_free(Logger *l)
{
    free(l->buf);
    file_close(l->fd);
}

int logger_next_timeout(Logger *l)
{
    Time now = get_current_time();
    if (now == INVALID_TIME)
        return 1000;

    if (l->len == 0)
        return -1;

    if (l->last_flush == INVALID_TIME)
        return 0;

    ASSERT(now >= l->last_flush);
    Time elapsed = now - l->last_flush;

    if (elapsed > l->timeout)
        return 0;

    return l->timeout - elapsed;
}

void logger_flush(Logger *l)
{
    int num = 0;
    while (num < l->len) {
        int ret = file_write(
            l->fd,
            l->buf + num,
            l->len - num);
        if (ret < 0) {
            ASSERT(0); // TODO
        }
        num += ret;
    }
    l->len = 0;
    l->last_flush = get_current_time(); // May return the invalid time
}

void log(Logger *l, string fmt, Args args)
{
    if (l == NULL)
        return;
    StringBuilder b;
    sb_init(&b,
        l->buf + l->len,
        l->cap - l->len);
    sb_write_fmt(&b, fmt, args);
    if (b.status < 0)
        return;
    if (b.len > l->cap - l->len) {
        ASSERT(0); // TODO
    }
    l->len += b.len;
}
