#ifndef TIME_INCLUDED
#define TIME_INCLUDED

#include "basic.h"

typedef u64 Time;

#define INVALID_TIME U64_MAX

// Returns the current time in milliseconds since
// an unspecified time in the past (useful to calculate
// elapsed time intervals)
Time get_current_time(void);

#endif // TIME_INCLUDED
