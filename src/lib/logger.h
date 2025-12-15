#ifndef LOGGER_INCLUDED
#define LOGGER_INCLUDED

#include "time.h"
#include "variadic.h"
#include "file_system.h"

typedef struct {
    char* buf;
    int   len;
    int   cap;
    FileHandle fd;
    int   timeout;
    Time  last_flush;
} Logger;

int  logger_init(Logger *l, int cap, int timeout, string path);
void logger_free(Logger *l);
int  logger_next_timeout(Logger *l);
int  logger_flush(Logger *l);
int  logger_flush_if_timeout(Logger *l);

void log(Logger *l, string fmt, Args args);

#endif // LOGGER_INCLUDED
