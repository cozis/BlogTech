#include "http.h"

string method_to_str(CHTTP_Method method)
{
    switch (method) {
    case CHTTP_METHOD_GET    : return S("GET");
    case CHTTP_METHOD_HEAD   : return S("HEAD");
    case CHTTP_METHOD_POST   : return S("POST");
    case CHTTP_METHOD_PUT    : return S("PUT");
    case CHTTP_METHOD_DELETE : return S("DELETE");
    case CHTTP_METHOD_CONNECT: return S("CONNECT");
    case CHTTP_METHOD_OPTIONS: return S("OPTIONS");
    case CHTTP_METHOD_TRACE  : return S("TRACE");
    case CHTTP_METHOD_PATCH  : return S("PATCH");
    default:break;
    }
    return S("???");
}
