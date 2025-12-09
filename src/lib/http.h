#ifndef HTTP_INCLUDED
#define HTTP_INCLUDED

#include "basic.h"
#include "../3p/chttp.h"

// Conversion macros between string (from basic.h) and CHTTP_String (from chttp.h)
#define S2H(X) (CHTTP_String) { (X).ptr, (X).len }
#define H2S(X)       (string) { (X).ptr, (X).len }

#endif // HTTP_INCLUDED
