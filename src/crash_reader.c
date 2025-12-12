#include "crash_reader.h"

int crash_reader_init(CrashReader *reader, string crash_file, string debug_info_file)
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
    reader->debug_info_file = debug_info_file;
    return 0;
}

void crash_reader_free(CrashReader *reader)
{
    if (reader->len > 0)
        free(reader->src);

    if (reader->cur > 0)
        addr2line_free_result(&reader->a2lres);
}

b8 crash_reader_next(CrashReader *reader, CrashInfo *crash)
{
    if (reader->cur == reader->len)
        return false;

    if (reader->cur > 0)
        addr2line_free_result(&reader->a2lres);
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

    int ret = addr2line(reader->debug_info_file, frames, num_frames, &reader->a2lres);
    if (ret < 0) {
        // Symbol resolution failed, return frames without symbol info
        crash->num_frames = 0;
        return true;
    }

    if (reader->a2lres.count > CRASH_FRAME_LIMIT)
        reader->a2lres.count = CRASH_FRAME_LIMIT;

    for (int i = 0; i < reader->a2lres.count; i++) {
        crash->frames[i].func = reader->a2lres.items[i].func;
        crash->frames[i].file = reader->a2lres.items[i].file;
        crash->frames[i].line = reader->a2lres.items[i].line;
    }
    crash->num_frames = reader->a2lres.count;

    return true;
}
