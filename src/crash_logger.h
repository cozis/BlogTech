#ifndef CRASH_LOGGER_INCLUDED
#define CRASH_LOGGER_INCLUDED

#define CRASH_FRAME_LIMIT 32

// These files are written to disk so should
// never change.
#define CRASH_TYPE_SEGV 1
#define CRASH_TYPE_BUS  2
#define CRASH_TYPE_ILL  3
#define CRASH_TYPE_FPE  4
#define CRASH_TYPE_TRAP 5
#define CRASH_TYPE_SYS  6
#define CRASH_TYPE_ABRT 7
#define CRASH_TYPE_OTH  8

#define CRASH_LOGGER_VERSION 0

typedef struct {

    // Version of the crash logger that generated
    // this entry.
    u16 version;

    // Type of crash. It's one of the CRASH_TYPE_XXX
    // values.
    u8  type;

    // Number of frames followed by this header.
    // Each frame is 8 bytes.
    u8 frames;

    // ID of the crashed process
    u32 process_id;

    // UTC time of the crash
    u64 timestamp;
} CrashHeader;

int  crash_logger_init(void);
void crash_logger_free(void);

#endif // CRASH_LOGGER_INCLUDED
