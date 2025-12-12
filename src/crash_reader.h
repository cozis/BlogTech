#ifndef CRASH_READER_INCLUDED
#define CRASH_READER_INCLUDED

#include "crash_logger.h"
#include "addr2line.h"
#include "lib/basic.h"

typedef struct {
    char *src;
    int   len;
    int   cur;
    string debug_info_file;
    Addr2LineResult a2lres;
} CrashReader;

typedef struct {
    string func;
    string file;
    int    line;
} CrashFrame;

typedef struct {
    string     type;
    u32        process_id;
    UnixTime   timestamp;
    int        num_frames;
    CrashFrame frames[CRASH_FRAME_LIMIT];
} CrashInfo;

int  crash_reader_init(CrashReader *reader, string crash_file, string debug_info_file);
void crash_reader_free(CrashReader *reader);
b8   crash_reader_next(CrashReader *reader, CrashInfo *crash);

#endif // CRASH_READER_INCLUDED