#ifndef EVENT_LOOP_INCLUDED
#define EVENT_LOOP_INCLUDED

#include <signal.h>

typedef struct {
    CHTTP_Server *server;
    CHTTP_Client *client;
    sig_atomic_t  running;
} EventLoop;

typedef enum {
    EVENT_EXIT,
    EVENT_TIMEOUT,
    EVENT_HTTP_REQUEST,
    EVENT_HTTP_RESPONSE,
} EventType;

typedef struct {
    EventType type;

    // EVENT_HTTP_REQUEST
    CHTTP_Request *request;
    CHTTP_ResponseBuilder builder;

    // EVENT_HTTP_RESPONSE
    int result;
    void *user;
    CHTTP_Response *response;

} Event;

void event_loop_init(EventLoop *loop,
    CHTTP_Server *server, CHTTP_Client *client);

void event_loop_free(EventLoop *loop);

Event event_loop_wait(EventLoop *loop,
    int *timeouts, int num_timeouts);

int event_loop_install_ctrlc_handler(EventLoop *event_loop);

#endif // EVENT_LOOP_INCLUDED