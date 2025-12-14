#include "event_loop.h"
#include "lib/time.h"

#ifdef _WIN32
#define POLL WSAPoll
#else
#define POLL poll
#endif

static EventLoop *loop_monitoring_ctrlc___;

#ifdef _WIN32
static BOOL WINAPI console_handler(DWORD event)
{
    switch (event) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        chttp_server_wakeup(loop_monitoring_ctrlc___->server);
        loop_monitoring_ctrlc___->running = 0;
        return TRUE;
    default:
        break;
    }
    return FALSE;
}
#else
static void signal_handler(int sig)
{
    loop_monitoring_ctrlc___->running = 0;
}
#endif

int event_loop_install_ctrlc_handler(EventLoop *loop)
{
    loop_monitoring_ctrlc___ = loop;
#ifdef _WIN32
    if (!SetConsoleCtrlHandler(console_handler, TRUE))
        return -1;
    return 0;
#else
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL); // TODO: can sigaction fail?
    sigaction(SIGTERM, &sa, NULL);
    return 0;
#endif
}

void event_loop_init(EventLoop *loop,
    CHTTP_Server *server, CHTTP_Client *client)
{
    loop->server = server;
    loop->client = client;
    loop->running = 1;
}

void event_loop_free(EventLoop *loop)
{
    (void) loop;
}

static int pick_timeout(int *arr, int num)
{
    int ret = -1;
    for (int i = 0; i < num; i++)
        if (arr[i] > -1) {
            if (ret == -1 || ret > arr[i])
                ret = arr[i];
        }
    return ret;
}

Event event_loop_wait(EventLoop *loop,
    int *timeouts, int num_timeouts)
{
    int general_timeout = pick_timeout(timeouts, num_timeouts);

    Time start_time;
    if (general_timeout < 0)
        start_time = INVALID_TIME;
    else {
        start_time = get_current_time();
        if (start_time == INVALID_TIME) {
            ASSERT(0);
        }
    }

    for (;;) {

        Event event;

        if (!loop_monitoring_ctrlc___->running) {
            event.type = EVENT_EXIT;
            return event;
        }

        if (chttp_client_next_response(loop->client,
            &event.result, &event.user, &event.response)) {
            event.type = EVENT_HTTP_RESPONSE;
            return event;
        }

        if (chttp_server_next_request(loop->server,
            &event.request, &event.builder)) {
            event.type = EVENT_HTTP_REQUEST;
            return event;
        }

        #define POLL_CAPACITY (CHTTP_CLIENT_POLL_CAPACITY + CHTTP_SERVER_POLL_CAPACITY)

        void *ptrs[POLL_CAPACITY];
        struct pollfd polled[POLL_CAPACITY];

        EventRegister server_reg = {
            ptrs,
            polled,
            0, -1
        };
        chttp_server_register_events(loop->server, &server_reg);

        EventRegister client_reg = {
            ptrs   + server_reg.num_polled,
            polled + server_reg.num_polled,
            0, -1
        };
        chttp_client_register_events(loop->client, &client_reg);

        int step_timeout;
        if (start_time == INVALID_TIME)
            step_timeout = -1;
        else {
            Time current_time = get_current_time();
            if (current_time == INVALID_TIME) {
                ASSERT(0);
            }
            ASSERT(current_time >= start_time);

            Time elapsed = current_time - start_time;
            if (elapsed > general_timeout)
                return (Event) { .type=EVENT_TIMEOUT };

            step_timeout = general_timeout - (int) elapsed;
        }

        if (server_reg.timeout > -1) {
            if (step_timeout < 0 || step_timeout > server_reg.timeout)
                step_timeout = server_reg.timeout;
        }

        if (client_reg.timeout > -1) {
            if (step_timeout < 0 || step_timeout > client_reg.timeout)
                step_timeout = client_reg.timeout;
        }

        POLL(polled, server_reg.num_polled + client_reg.num_polled, step_timeout);

        chttp_client_process_events(loop->client, client_reg);
        chttp_server_process_events(loop->server, server_reg);
    }
}