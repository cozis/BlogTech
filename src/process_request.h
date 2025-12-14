#ifndef PROCESS_REQUEST_INCLUDED
#define PROCESS_REQUEST_INCLUDED

#include "auth.h"
#include "lib/http.h"

void process_request(
    string document_root,
    string host_dir,
    CHTTP_Request *request,
    CHTTP_ResponseBuilder builder,
    Auth *auth);

#endif // PROCESS_REQUEST_INCLUDED
