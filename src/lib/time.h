#ifndef TIME_INCLUDED
#define TIME_INCLUDED

#include "basic.h"

typedef u64 Time;
typedef u64 UnixTime;

#define INVALID_TIME ((Time) U64_MAX)
#define INVALID_UNIX_TIME ((UnixTime) U64_MAX)

#define TIME_MAX ((Time) U64_MAX - 1)
#define UNIX_TIME_MAX ((UnixTime) U64_MAX - 1)

// Returns the current time in milliseconds since
// an unspecified time in the past (useful to calculate
// elapsed time intervals)
Time get_current_time(void);

// Number of seconds since 1 Jan, 1970 UTC
//
// Signal-safe
UnixTime get_current_unix_time(void);

#endif // TIME_INCLUDED
