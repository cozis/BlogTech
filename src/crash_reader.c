#include "crash_reader.h"

int crash_reader_init(CrashReader *reader, string crash_file)
{
    string data;
    int ret = file_read_all(crash_file, &data);
    if (ret < 0) {
        if (ret != FS_ERROR_NOTFOUND)
            return -1;
        data = EMPTY_STRING;
    }

    reader->src = data.ptr;
    reader->len = data.len;
    reader->cur = 0;
    return 0;
}

void crash_reader_free(CrashReader *reader)
{
    if (reader->len > 0)
        free(reader->src);

#ifndef _WIN32
    if (reader->cur > 0)
        addr2line_free_result(&reader->a2lres);
#endif
}

b8 crash_reader_next(CrashReader *reader, CrashInfo *crash)
{
    if (reader->cur == reader->len)
        return false;

#ifndef _WIN32
    if (reader->cur > 0)
        addr2line_free_result(&reader->a2lres);
#endif
    //////////////////////////////////////////////
    // Read header

    CrashHeader header;
    if (reader->len - reader->cur < SIZEOF(header)) {
        reader->cur = reader->len;
        return false;
    }
    memcpy(&header, reader->src + reader->cur, sizeof(header));
    reader->cur += sizeof(header);

    if (header.version != CRASH_LOGGER_VERSION) {
        ASSERT(0); // TODO
    }

    if (header.frames > CRASH_FRAME_LIMIT) {
        ASSERT(0); // TODO
    }

    int num_frames;
    u64 frames[CRASH_FRAME_LIMIT];
    if (reader->len - reader->cur < header.frames * sizeof(u64)) {
        reader->cur = reader->len;
        return false;
    }
    memcpy(&frames, reader->src + reader->cur, header.frames * sizeof(u64));
    reader->cur += header.frames * sizeof(u64);
    num_frames = header.frames;

    //////////////////////////////////////////////
    // Set output

    switch (header.type) {
    case CRASH_TYPE_SEGV: crash->type = S("Segmentation fault");       break;
    case CRASH_TYPE_BUS : crash->type = S("Bus error");                break;
    case CRASH_TYPE_ILL : crash->type = S("Illegal instruction");      break;
    case CRASH_TYPE_FPE : crash->type = S("Floating point exception"); break;
    case CRASH_TYPE_TRAP: crash->type = S("Trace trap");               break;
    case CRASH_TYPE_SYS : crash->type = S("Bad system call");          break;
    case CRASH_TYPE_ABRT: crash->type = S("Abort");                    break;
    case CRASH_TYPE_OTH : crash->type = S("(unknown)");                break;
    }
    crash->process_id = header.process_id;
    crash->timestamp = header.timestamp;

#ifdef _WIN32
    // TODO
    crash->num_frames = 0;
#else
    Addr2LineResult a2lres;
    int ret = addr2line(S("blogtech"), frames, num_frames, &reader->a2lres);
    if (ret < 0) {
        ASSERT(0);
    }

    if (reader->a2lres.count > CRASH_FRAME_LIMIT)
        reader->a2lres.count = CRASH_FRAME_LIMIT;

    for (int i = 0; i < reader->a2lres.count; i++) {
        crash->frames[i].func = reader->a2lres.items[i].func;
        crash->frames[i].file = reader->a2lres.items[i].file;
        crash->frames[i].line = reader->a2lres.items[i].line;
    }
    crash->num_frames = reader->a2lres.count;
#endif

    return true;
}
