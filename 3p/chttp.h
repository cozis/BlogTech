#ifndef HTTP_INCLUDED
#define HTTP_INCLUDED
// cHTTP, an HTTP client and server library!
//
// This file was generated automatically. Do not modify directly.
//
// Refer to the end of this file for the license
////////////////////////////////////////////////////////////////////////////////////////
// src/includes.h
////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <limits.h>
#include <stdarg.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#ifdef HTTPS_ENABLED
#include <openssl/ssl.h>
#endif

////////////////////////////////////////////////////////////////////////////////////////
// src/basic.h
////////////////////////////////////////////////////////////////////////////////////////

enum {

    HTTP_OK                = 0,

    // A generic error occurred
    HTTP_ERROR_UNSPECIFIED = -1,

    // Out of memory
    HTTP_ERROR_OOM         = -2,

    // Invalid URL
    HTTP_ERROR_BADURL      = -3,

    // Parallel request limit reached
    HTTP_ERROR_REQLIMIT    = -4,

    // Invalid handle
    HTTP_ERROR_BADHANDLE   = -5,

    // TLS support not built-in
    HTTP_ERROR_NOTLS       = -6,
};

// String type used throughout cHTTP.
typedef struct {
	char *ptr;
	int   len;
} HTTP_String;

// Compare two strings and return true iff they have
// the same contents.
bool http_streq(HTTP_String s1, HTTP_String s2);

// Compre two strings case-insensitively (uppercase and
// lowercase versions of a letter are considered the same)
// and return true iff they have the same contents.
bool http_streqcase(HTTP_String s1, HTTP_String s2);

// Remove spaces and tabs from the start and the end of
// a string. This doesn't change the original string and
// the new one references the contents of the original one.
HTTP_String http_trim(HTTP_String s);

// Print the contents of a byte string with the given prefix.
// This is primarily used for debugging purposes.
void print_bytes(HTTP_String prefix, HTTP_String src);

// TODO: comment
char *http_strerror(int code);

// Macro to simplify converting string literals to
// HTTP_String.
//
// Instead of doing this:
//
//   char *s = "some string";
//
// You do this:
//
//   HTTP_String s = HTTP_STR("some string")
//
// This is a bit cumbersome, but better than null-terminated
// strings, having a pointer and length variable pairs whenever
// a function operates on a string. If this wasn't a library
// I would have done for
//
//   #define S(X) ...
//
// But I don't want to cause collisions with user code.
#define HTTP_STR(X) ((HTTP_String) {(X), sizeof(X)-1})

// Returns the number of items of a static array.
#define HTTP_COUNT(X) (sizeof(X) / sizeof((X)[0]))

// Macro to unpack an HTTP_String into its length and pointer components.
// Useful for passing HTTP_String to printf-style functions with "%.*s" format.
// Example: printf("%.*s", HTTP_UNPACK(str));
#define HTTP_UNPACK(X) (X).len, (X).ptr

// TODO: comment
#define HTTP_UNREACHABLE __builtin_trap()

////////////////////////////////////////////////////////////////////////////////////////
// src/parse.h
////////////////////////////////////////////////////////////////////////////////////////

#define HTTP_MAX_HEADERS 32

typedef struct {
	unsigned int data;
} HTTP_IPv4;

typedef struct {
	unsigned short data[8];
} HTTP_IPv6;

typedef enum {
	HTTP_HOST_MODE_VOID = 0,
	HTTP_HOST_MODE_NAME,
	HTTP_HOST_MODE_IPV4,
	HTTP_HOST_MODE_IPV6,
} HTTP_HostMode;

typedef struct {
	HTTP_HostMode mode;
	HTTP_String   text;
	union {
		HTTP_String name;
		HTTP_IPv4   ipv4;
		HTTP_IPv6   ipv6;
	};
} HTTP_Host;

typedef struct {
	HTTP_String userinfo;
	HTTP_Host   host;
	int         port;
} HTTP_Authority;

// ZII
typedef struct {
	HTTP_String    scheme;
	HTTP_Authority authority;
	HTTP_String    path;
	HTTP_String    query;
	HTTP_String    fragment;
} HTTP_URL;

typedef enum {
	HTTP_METHOD_GET,
	HTTP_METHOD_HEAD,
	HTTP_METHOD_POST,
	HTTP_METHOD_PUT,
	HTTP_METHOD_DELETE,
	HTTP_METHOD_CONNECT,
	HTTP_METHOD_OPTIONS,
	HTTP_METHOD_TRACE,
	HTTP_METHOD_PATCH,
} HTTP_Method;

typedef struct {
	HTTP_String name;
	HTTP_String value;
} HTTP_Header;

typedef struct {
    bool        secure;
	HTTP_Method method;
	HTTP_URL    url;
	int         minor;
	int         num_headers;
	HTTP_Header headers[HTTP_MAX_HEADERS];
	HTTP_String body;
} HTTP_Request;

typedef struct {
    void*       context;
	int         minor;
	int         status;
	HTTP_String reason;
	int         num_headers;
	HTTP_Header headers[HTTP_MAX_HEADERS];
	HTTP_String body;
} HTTP_Response;

int         http_parse_ipv4     (char *src, int len, HTTP_IPv4     *ipv4);
int         http_parse_ipv6     (char *src, int len, HTTP_IPv6     *ipv6);
int         http_parse_url      (char *src, int len, HTTP_URL      *url);
int         http_parse_request  (char *src, int len, HTTP_Request  *req);
int         http_parse_response (char *src, int len, HTTP_Response *res);

int         http_find_header    (HTTP_Header *headers, int num_headers, HTTP_String name);

HTTP_String http_get_cookie     (HTTP_Request *req, HTTP_String name);
HTTP_String http_get_param      (HTTP_String body, HTTP_String str, char *mem, int cap);
int         http_get_param_i    (HTTP_String body, HTTP_String str);

// Checks whether the request was meant for the host with the given
// domain an port. If port is -1, the default value of 80 is assumed.
bool http_match_host(HTTP_Request *req, HTTP_String domain, int port);

// Date and cookie types for Set-Cookie header parsing
typedef enum {
    HTTP_WEEKDAY_MON,
    HTTP_WEEKDAY_TUE,
    HTTP_WEEKDAY_WED,
    HTTP_WEEKDAY_THU,
    HTTP_WEEKDAY_FRI,
    HTTP_WEEKDAY_SAT,
    HTTP_WEEKDAY_SUN,
} HTTP_WeekDay;

typedef enum {
    HTTP_MONTH_JAN,
    HTTP_MONTH_FEB,
    HTTP_MONTH_MAR,
    HTTP_MONTH_APR,
    HTTP_MONTH_MAY,
    HTTP_MONTH_JUN,
    HTTP_MONTH_JUL,
    HTTP_MONTH_AUG,
    HTTP_MONTH_SEP,
    HTTP_MONTH_OCT,
    HTTP_MONTH_NOV,
    HTTP_MONTH_DEC,
} HTTP_Month;

typedef struct {
    HTTP_WeekDay week_day;
    int          day;
    HTTP_Month   month;
    int          year;
    int          hour;
    int          minute;
    int          second;
} HTTP_Date;

typedef struct {
    HTTP_String name;
    HTTP_String value;

    bool secure;
    bool http_only;

    bool have_date;
    HTTP_Date date;

    bool have_max_age;
    uint32_t max_age;

    bool have_domain;
    HTTP_String domain;

    bool have_path;
    HTTP_String path;
} HTTP_SetCookie;

// Parses a Set-Cookie header value
// Returns 0 on success, -1 on error
int http_parse_set_cookie(HTTP_String str, HTTP_SetCookie *out);

////////////////////////////////////////////////////////////////////////////////////////
// src/secure_context.h
////////////////////////////////////////////////////////////////////////////////////////

#ifndef SERVER_CERTIFICATE_LIMIT
// Maximum number of certificates that can be
// associated to a TLS server. This doesn't include
// the default certificate.
#define SERVER_CERTIFICATE_LIMIT 8
#endif

int global_secure_context_init(void);
int global_secure_context_free(void);

typedef struct {
#ifdef HTTPS_ENABLED
    SSL_CTX *p;
#endif
} ClientSecureContext;

int  client_secure_context_init(ClientSecureContext *ctx);
void client_secure_context_free(ClientSecureContext *ctx);

typedef struct {
#ifdef HTTPS_ENABLED
    char domain[128];
    SSL_CTX *ctx;
#endif
} ServerCertificate;

typedef struct {
#ifdef HTTPS_ENABLED
    SSL_CTX *p;
    int num_certs;
    ServerCertificate certs[SERVER_CERTIFICATE_LIMIT];
#endif
} ServerSecureContext;

int server_secure_context_init(ServerSecureContext *ctx,
    HTTP_String cert_file, HTTP_String key_file);
void server_secure_context_free(ServerSecureContext *ctx);
int  server_secure_context_add_certificate(ServerSecureContext *ctx,
    HTTP_String domain, HTTP_String cert_file, HTTP_String key_file);

////////////////////////////////////////////////////////////////////////////////////////
// src/socket.h
////////////////////////////////////////////////////////////////////////////////////////
// This file (and its relative .c file) implements an asynchronous TCP/TLS
// server and client abstraction.
//
// It introduces the concept of a "socket manager", which is a pool of
// connection sockets and a listener socket. The listener is managed
// internally, which means the manager automatically accepts sockets
// from it and adds them to the pool.
//
// If the listener is configured using the function:
//
//   socket_manager_listen_tcp
//
// the resulting connections will not use TLS. If instead the listener
// is configured using:
//
//   socket_manager_listen_tls
//
// the listener will use TLS. Note that both functions can be used on
// the same manager to allow both plaintext and encrypted connections.
// Users may enable zero listeners, in which case only outgoing
// connections are allowed (more on this later).
//
// Once the manager is set up, one can wait for events by following
// this pattern:
//
//   struct pollfd polled[...];
//   int num_polled = socket_manager_register_events(sm, polled, max_polled);
//   poll(polled, num_polled, -1);
//
//   #define MAX_EVENTS ...
//   SocketEvent events[MAX_EVENTS];
//   int num_events = socket_manager_translate_events(sm, events, MAX_EVENTS, polled, num_polled);
//   for (int i = 0; i < num_events; i++) {
//     ... Here call socket_recv, socket_send, socket_close, ...
//   }
//
// Note that from the user's perspective, there is no difference
// between connections that use plain TCP and those that use TCP/TLS.
//
// Users can also establish outgoing connections by calling the
// function:
//
//   socket_connect
//
// Which allows the creation of a connection towards an host given
// its domain, IPv4, IPv6, or an array of them. This can be done both
// for TCP and TCP/TLS connection. Note that users that only intend
// to establish outgoing connection may omit the configuration of
// listeners entirely.

#ifdef _WIN32
#define NATIVE_SOCKET         SOCKET
#define NATIVE_SOCKET_INVALID SOCKET_ERROR
#define CLOSE_NATIVE_SOCKET   closesocket
#else
#define NATIVE_SOCKET         int
#define NATIVE_SOCKET_INVALID -1
#define CLOSE_NATIVE_SOCKET   close
#endif

typedef uint32_t SocketHandle;
#define SOCKET_HANDLE_INVALID ((SocketHandle) 0)

typedef uint16_t Port;

typedef enum {
    SOCKET_EVENT_READY,
    SOCKET_EVENT_DISCONNECT,
} SocketEventType;

typedef struct {
    SocketEventType type;
    SocketHandle    handle;
    void*           user;
} SocketEvent;

// Internal use only
typedef enum {

    // The Socket struct is unused
    SOCKET_STATE_FREE,

    // The state associated to a socket created
    // by a connect operation that hasn't been
    // processed yet.
    SOCKET_STATE_PENDING,

    // A connect() operation was started but is
    // still pending.
    SOCKET_STATE_CONNECTING,

    // Outgoing connection was established, but
    // a TLS handshake may need to be performed.
    SOCKET_STATE_CONNECTED,

    // Incoming connection was established, but
    // a TLS handshake may need to be performed.
    SOCKET_STATE_ACCEPTED,

    // The connection was esablished, but the user
    // wants to perform a read or write operation that
    // would block.
    SOCKET_STATE_ESTABLISHED_WAIT,

    // The connection was established and it's possible
    // to perform read or write operations on it without
    // blocking.
    SOCKET_STATE_ESTABLISHED_READY,

    // The socket was marked to be closed.
    SOCKET_STATE_SHUTDOWN,

    // The current socket is was closed. The only
    // valid thing to do here is free its resources.
    SOCKET_STATE_DIED,
} SocketState;

typedef struct {
    int  refs;
    char data[];
} RegisteredName;

// Internal use only
typedef struct {
    union {
        HTTP_IPv4 ipv4;
        HTTP_IPv6 ipv6;
    };
    bool is_ipv4;
    Port port;

#ifdef HTTPS_ENABLED
    // When connecting to a peer using TLS, if the address
    // was resolved from a registered name, that name is
    // used to request the correct certificate once the TCP
    // handshake is established, and therefore need to
    // store it somewhere until that happens.
    RegisteredName *name;
#endif
} AddressAndPort;

// Internal use only
typedef struct {
    SocketState state;

    // OS-specific socket type
    NATIVE_SOCKET sock;

    // Native socket events that need to be monitored
    int events;

    // Generation counter to invalidate any SocketHandle
    // referring to this socket when it is freed.
    // Note that this counter may wrap but always skips
    // the 0 value to ensure the 0 SocketHandle is always
    // invalid.
    uint16_t gen;

    // User-provided context pointer
    void *user;

    // A single connect operation may involve
    // trying to establish a connection towards
    // one of a set of addresses.
    int num_addr;
    int next_addr;
    union {
        AddressAndPort addr; // When num_addr=1
        AddressAndPort *addrs; // Dynamically allocated when num_addr>1
    };

#ifdef HTTPS_ENABLED
    ClientSecureContext *client_secure_context;
    ServerSecureContext *server_secure_context;
    SSL *ssl;
#endif

} Socket;

// Glorified array of sockets. This structure
// is private to the .c file associated to this
// header.
typedef struct {

    // TCP listener sockets. The first is intended
    // for plaintext, while the second is for TLS.
    // The socket manager will accept and add new
    // sockets to the pool automatically. Note that
    // either may be unset. If both are unset, users
    // can only create outgoing connections.
    NATIVE_SOCKET plain_sock;
    NATIVE_SOCKET secure_sock;

    // Handles for the self-pipe trick necessary for
    // other threads to wake up sockets blocked on
    // poll().
    NATIVE_SOCKET wait_sock;
    NATIVE_SOCKET signal_sock;

    // TLS contexts. One is used for outgoing connections
    // (the client context) and one for incoming
    // connections (server). If the secure_sock is
    // set, the server context is initialized. If at
    // least one connect was performed using TLS
    // (and the flag is set), the client context is
    // initialized.
    bool at_least_one_secure_connect;
    ClientSecureContext client_secure_context;
    ServerSecureContext server_secure_context;

    // If the socket manager needed to initialize some
    // global state for its initialization, this flag
    // will be set so that it will remember to cleanup
    // that state during deinitialization.
    bool global_cleanup;

    // Array of sockets. Structs with state FREE
    // are unused.
    int num_used;
    int max_used;
    Socket *sockets;

} SocketManager;

// Instanciate a socket manager. Returns 0 on
// success and -1 on error.
int socket_manager_init(SocketManager *sm, Socket *socks,
    int num_socks);

// Deinitialize a socket manager
void socket_manager_free(SocketManager *sm);

// Configure the socket manager to listen on
// the specified interface for TCP connections.
// Incoming connections will be automatically
// added to the internal pool. This function
// can only be used once per manager.
// Returns 0 on success, -1 on error.
int socket_manager_listen_tcp(SocketManager *sm,
    HTTP_String addr, Port port, int backlog,
    bool reuse_addr);

// Same as the previous function, but incoming
// connections will be interpreted as TLS. You
// can only call this function once per manager,
// but you can call this and the plaintext variant
// on the same manager to accept both plaintext
// and secure connections.
// Returns 0 on success, -1 on error.
int socket_manager_listen_tls(SocketManager *sm,
    HTTP_String addr, Port port, int backlog,
    bool reuse_addr, HTTP_String cert_file,
    HTTP_String key_file);

// If the socket manager was configures to accept
// TLS connections, this adds additional certificates
// the client can use to verify the server's
// authenticity.
// Returns 0 on success, -1 on error.
int socket_manager_add_certificate(SocketManager *sm,
    HTTP_String domain, HTTP_String cert_file, HTTP_String key_file);

// When a thread is blocked on a poll() call for
// descriptors associated to this socket manager,
// other threads can call this function to wake
// up that blocked thread.
// Returns 0 on success, -1 on error.
int socket_manager_wakeup(SocketManager *sm);

typedef struct {
    void **ptrs;
    struct pollfd *polled;
    int num_polled;
} EventRegister;

// Resets the event register with the list of descriptors
// the socket manager wants monitored.
void socket_manager_register_events(SocketManager *sm,
    EventRegister *reg);

// After poll() is called on the previously registered
// pollfd array and the revents fields are set, this
// function processes those events to produce higher-level
// socket events. Returns the number of socket events
// written to the output array, or -1 on error.
//
// The maximum number of events this will write
// to the events array is equal to the numero of
// socket structs provided to the socket manager
// via the init function.
int socket_manager_translate_events(SocketManager *sm,
    SocketEvent *events, EventRegister reg);

typedef enum {
    CONNECT_TARGET_NAME,
    CONNECT_TARGET_IPV4,
    CONNECT_TARGET_IPV6,
} ConnectTargetType;

typedef struct {
    ConnectTargetType type;
    Port port;
    union {
        HTTP_IPv4 ipv4;
        HTTP_IPv6 ipv6;
        HTTP_String name;
    };
} ConnectTarget;

// Connect to one of the given targets. The socket
// manager will try to connecting to addresses until
// one succedes. If secure=true, the socket uses TLS.
// Returns 0 on success, -1 on error.
int socket_connect(SocketManager *sm, int num_targets,
    ConnectTarget *targets, bool secure, void *user);

int socket_recv(SocketManager *sm, SocketHandle handle,
    char *dst, int max);

int socket_send(SocketManager *sm, SocketHandle handle,
    char *src, int len);

void socket_close(SocketManager *sm, SocketHandle handle);

// Returns -1 on error, 0 if the socket was accepted
// from the plaintext listener, or 1 if it was accepted
// by the secure listener.
bool socket_is_secure(SocketManager *sm, SocketHandle handle);

// Set the user pointer of a socket
void socket_set_user(SocketManager *sm, SocketHandle handle, void *user);

// Returns true iff the socket is ready for reading or
// writing.
bool socket_ready(SocketManager *sm, SocketHandle handle);

////////////////////////////////////////////////////////////////////////////////////////
// src/byte_queue.h
////////////////////////////////////////////////////////////////////////////////////////
// This is the implementation of a byte queue useful
// for systems that need to process engs of bytes.
//
// It features sticky errors, a zero-copy interface,
// and a safe mechanism to patch previously written
// bytes.
//
// Only up to 4GB of data can be stored at once.

// Internal use only
enum {
    BYTE_QUEUE_ERROR = 1 << 0,
    BYTE_QUEUE_READ  = 1 << 1,
    BYTE_QUEUE_WRITE = 1 << 2,
};

typedef struct {
    uint8_t *ptr;
    size_t   len;
} ByteView;

// Fields are for internal use only
typedef struct {
    uint64_t curs;
    uint8_t* data;
    uint32_t head;
    uint32_t size;
    uint32_t used;
    uint32_t limit;
    uint8_t* read_target;
    uint32_t read_target_size;
    int flags;
} ByteQueue;

// Represents an offset inside the queue relative
// to the first byte ever appended to the queue,
// therefore consuming bytes from the queue does
// not invalidate this type of offset.
typedef uint64_t ByteQueueOffset;

// Initialize the queue with a given capacity limit.
// This is just a soft limit. The queue will allocate
// dynamically as needed up to this limit and won't
// grow further. When the limit is reached, http_queue_full
// returns true.
void byte_queue_init(ByteQueue *queue, uint32_t limit);

// Free resources associated to this queue
void byte_queue_free(ByteQueue *queue);

// Check whether an error occurred inside the queue
int byte_queue_error(ByteQueue *queue);

// Returns 1 if the queue has no bytes inside it,
// or 0 otherwise.
int byte_queue_empty(ByteQueue *queue);

// Returns 1 if the queue reached its limit, or 0
// otherwise.
int byte_queue_full(ByteQueue *queue);

// These two functions are to be used together.
// read_buf returns a view into the queue of the
// bytes that can be read from it. The caller can
// decide how many of those bytes can be removed
// by passing the count to the read_ack function.
// If an error occurred inside the queue, this
// function returns an empty view.
//
// Note that the calls to read_buf and read_ack
// may be far apart. Other operations won't interfere
// with the read. The only rule is you can't call
// read_buf multiple times before calling read_ack.
ByteView byte_queue_read_buf(ByteQueue *queue);
void     byte_queue_read_ack(ByteQueue *queue, uint32_t num);

// Similar to the read_buf/read_ack functions,
// but write_buf returns a view of the unused
// memory inside the queue, and write_ack is
// used to tell the queue how many bytes were
// written into it. Note that to ensure there
// is a minimum amount of free space in the queue,
// the user needs to call byte_queue_setmincap.
// If an error occurred inside the queue, this
// function returns an empty view.
//
// Note that the calls to write_buf and write_ack
// may be far apart. Other operations won't interfere
// with the write (except for other byte_queue_write_*
// functions). The only rule is you can't call
// write_buf multiple times before calling write_ack.
ByteView byte_queue_write_buf(ByteQueue *queue);
void     byte_queue_write_ack(ByteQueue *queue, uint32_t num);

// Sets the minimum capacity for the next write
// operation and returns 1 if the content of the
// queue was moved, else 0 is returned.
//
// You must not call this function while a write
// is pending. In other words, you must do this:
//
//   byte_queue_write_setmincap(queue, mincap);
//   dst = byte_queue_write_buf(queue, &cap);
//   ...
//   byte_queue_write_ack(num);
//
// And NOT this:
//
//   dst = byte_queue_write_buf(queue);
//   byte_queue_write_setmincap(queue, mincap); <-- BAD
//   ...
//   byte_queue_write_ack(num);
//
int byte_queue_write_setmincap(ByteQueue *queue, uint32_t mincap);

// Write some bytes to the queue. This is a
// short hand for write_buf/memcpy/write_ack
void byte_queue_write(ByteQueue *queue, void *ptr, uint32_t len);

// Write the result of the format into the queue
void byte_queue_write_fmt(ByteQueue *queue, const char *fmt, ...);

// Write the result of the format into the queue
void byte_queue_write_fmt2(ByteQueue *queue, const char *fmt,
    va_list args);

// Returns the current offset inside the queue
ByteQueueOffset byte_queue_offset(ByteQueue *queue);

// Writes some bytes at the specified offset. It's
// the responsibility of the user to make sure that
// the offset still refers to content inside the queue.
void byte_queue_patch(ByteQueue *queue, ByteQueueOffset off, void *src, uint32_t len);

// Returns the number of bytes from the given offset
// to the end of the queue.
uint32_t byte_queue_size_from_offset(ByteQueue *queue, ByteQueueOffset off);

// Removes all bytes from the given offset to the the
// end of the queue.
void byte_queue_remove_from_offset(ByteQueue *queue, ByteQueueOffset offset);

////////////////////////////////////////////////////////////////////////////////////////
// src/cert.h
////////////////////////////////////////////////////////////////////////////////////////
// This is an utility to create self-signed certificates
// useful when testing HTTPS servers locally. This is only
// meant to be used by people starting out with a library
// and simplifying the zero to one phase.
//
// The C, O, and CN are respectively country name, organization name,
// and common name of the certificate. For instance:
//
//   C="IT"
//   O="My Organization"
//   CN="my_website.com"
//
// The output is a certificate file in PEM format and a private
// key file with the key used to sign the certificate.
int http_create_test_certificate(HTTP_String C, HTTP_String O, HTTP_String CN,
    HTTP_String cert_file, HTTP_String key_file);

////////////////////////////////////////////////////////////////////////////////////////
// src/client.h
////////////////////////////////////////////////////////////////////////////////////////

#ifndef HTTP_CLIENT_CAPACITY
// The maximum ammount of requests that can be performed
// in parallel.
#define HTTP_CLIENT_CAPACITY (1<<7)
#endif

// Maximum number of descriptors the client will want
// to wait on. It's one per connection plus the wakeup
// self-pipe.
#define HTTP_CLIENT_POLL_CAPACITY (HTTP_CLIENT_CAPACITY+1)

#ifndef HTTP_COOKIE_JAR_CAPACITY
// Maximum number of cookies that can be associated to a
// single client.
#define HTTP_COOKIE_JAR_CAPACITY 128
#endif

typedef struct {

    // Cookie name and value
    HTTP_String name;
    HTTP_String value;

    // If the "exact_domain" is true, the cookie
    // can only be sent to the exact domain referred
    // to by "domain" (which is never empty). If
    // "exact_domain" is false, then the cookie is
    // compatible with subdomains.
    bool exact_domain;
    HTTP_String domain;

    // If "exact_path" is set, the cookie is only
    // compatible with requests to paths that match
    // "path" exactly. If "exact_path" is not set,
    // then any path that starts with "path" is
    // compatible with the cookie.
    bool exact_path;
    HTTP_String path;

    // This cookie can only be sent over HTTPS
    bool secure;

} HTTP_CookieJarEntry;

typedef struct {
    int count;
    HTTP_CookieJarEntry items[HTTP_COOKIE_JAR_CAPACITY];
} HTTP_CookieJar;

typedef enum {
    HTTP_CLIENT_CONN_FREE,
    HTTP_CLIENT_CONN_WAIT_METHOD,
    HTTP_CLIENT_CONN_WAIT_URL,
    HTTP_CLIENT_CONN_WAIT_HEADER,
    HTTP_CLIENT_CONN_WAIT_BODY,
    HTTP_CLIENT_CONN_FLUSHING,
    HTTP_CLIENT_CONN_BUFFERING,
    HTTP_CLIENT_CONN_COMPLETE,
} HTTP_ClientConnState;

// Fields of this struct are private
typedef struct HTTP_Client HTTP_Client;

typedef struct {
    HTTP_ClientConnState state;

    // Handle to the socket
    SocketHandle handle;

    // Pointer back to the client
    HTTP_Client *client;

    // Generation counter for request builder validation
    uint16_t gen;

    // Opaque pointer set by the user while building
    // the request. It's returned alongside the result.
    void *user;

    // TODO: comment
    bool trace_bytes;

    // Allocated copy of the URL string
    HTTP_String url_buffer;

    // Parsed URL for connection establishment
    // All url.* pointers reference into url_buffer
    HTTP_URL url;

    // Data received from the server
    ByteQueue input;

    // Data being sent to the server
    ByteQueue output;

    // If the request is COMPLETE, indicates
    // whether it completed with an error (-1)
    // or a success (0). If it was a success,
    // the response field is valid.
    int result;

    // Parsed response once complete
    HTTP_Response response;
} HTTP_ClientConn;

// Fields of this struct are private
struct HTTP_Client {

    // Size limit of the input and output buffer of each
    // connection.
    uint32_t input_buffer_limit;
    uint32_t output_buffer_limit;

    // List of cookies created during this session
    HTTP_CookieJar cookie_jar;

    // Array of connections. The counter contains the
    // number of structs such that state!=FREE.
    int num_conns;
    HTTP_ClientConn conns[HTTP_CLIENT_CAPACITY];

    // Queue of indices referring to connections that
    // are in the COMPLETE state.
    int num_ready;
    int ready_head;
    int ready[HTTP_CLIENT_CAPACITY];

    // Asynchronous TCP and TLS socket abstraction
    SocketManager sockets;

    // The client object doesn't interact with this
    // field directly, it just initializes the socket
    // manager with a pointer to it. This allows
    // allocating the exact number of sockets we
    // will need.
    Socket socket_pool[HTTP_CLIENT_CAPACITY];
};

// Initialize an HTTP client object. This allows one to
// perform a number of requests in parallel.
int http_client_init(HTTP_Client *client);

// Release resources associated to a client object.
void http_client_free(HTTP_Client *client);

// Set input and output buffer size limit for any
// given connection. The default value is 1MB
void http_client_set_input_limit(HTTP_Client *client, uint32_t limit);
void http_client_set_output_limit(HTTP_Client *client, uint32_t limit);

// When a thread is blocked waiting for client events,
// other threads can call this function to wake it up.
int http_client_wakeup(HTTP_Client *client);

typedef struct {
    HTTP_Client *client;
    uint16_t index;
    uint16_t gen;
} HTTP_RequestBuilder;

// Create a new request builder object.
HTTP_RequestBuilder http_client_get_builder(HTTP_Client *client);

// TODO: comment
void http_request_builder_set_user(HTTP_RequestBuilder builder,
    void *user);

// TODO: comment
void http_request_builder_trace(HTTP_RequestBuilder builder,
    bool trace_bytes);

// Set the method of the current request. This is the first
// function of the request builder that the user must call.
void http_request_builder_method(HTTP_RequestBuilder builder,
    HTTP_Method method);

// Set the URL of the current request. This must be set after
// the method and before any header/body
void http_request_builder_target(HTTP_RequestBuilder builder,
    HTTP_String url);

// After the URL, the user may set zero or more headers.
void http_request_builder_header(HTTP_RequestBuilder builder,
    HTTP_String str);

// Append bytes to the request's body. You can call this
// any amount of times, as long as it's after having set
// the URL.
void http_request_builder_body(HTTP_RequestBuilder builder,
    HTTP_String str);

// Mark this request as complete. This invalidates the
// builder.
// Returns 0 on success, -1 on error.
int http_request_builder_send(HTTP_RequestBuilder builder);

// Resets the event register with the list of descriptors
// the client wants monitored.
void http_client_register_events(HTTP_Client *client,
    EventRegister *reg);

// The caller has waited for poll() to return and some
// I/O events to be triggered, so now the HTTP client
// can continue its buffering and flushing operations.
void http_client_process_events(HTTP_Client *client,
    EventRegister reg);

// After some I/O events were processes, some responses
// may be availabe. This function returns one of the
// buffered responses. If a request was available, true
// is returned. If no more are avaiable, false is returned.
// The returned response must be freed using the
// http_free_response function.
// TODO: Better comment talking about output arguments
bool http_client_next_response(HTTP_Client *client,
    int *result, void **user, HTTP_Response **response);

// TODO: comment
void http_client_wait_response(HTTP_Client *client,
    int *result, void **user, HTTP_Response **response);

// Free a response object. You can't access its fields
// again after this.
void http_free_response(HTTP_Response *response);

// Perform a blocking GET request
int http_get(HTTP_String url, HTTP_String *headers,
    int num_headers, HTTP_Response **response);

// Perform a blocking POST request
int http_post(HTTP_String url, HTTP_String *headers,
    int num_headers, HTTP_String body,
    HTTP_Response **response);

// Perform a blocking PUT request
int http_put(HTTP_String url, HTTP_String *headers,
    int num_headers, HTTP_String body,
    HTTP_Response **response);

// Perform a blocking DELETE request
int http_delete(HTTP_String url, HTTP_String *headers,
    int num_headers, HTTP_Response **response);

////////////////////////////////////////////////////////////////////////////////////////
// src/server.h
////////////////////////////////////////////////////////////////////////////////////////

#ifndef HTTP_SERVER_CAPACITY
// The maximum ammount of requests that can be handled
// in parallel.
#define HTTP_SERVER_CAPACITY (1<<9)
#endif

// Maximum number of descriptors the server will want
// to wait on. It's one per connection plus two for the
// TCP and TLS listener, plus one for the wakeup self-pipe.
#define HTTP_SERVER_POLL_CAPACITY (HTTP_SERVER_CAPACITY+3)

typedef enum {

    // This struct is unused
    HTTP_SERVER_CONN_FREE,

    // No request was buffered yet.
    HTTP_SERVER_CONN_BUFFERING,

    // A request was just buffered and is waiting for
    // the user to build a response. To be specific,
    // it's waiting for the user to set a response status.
    HTTP_SERVER_CONN_WAIT_STATUS,

    // A request is buffered and a status was set. Now
    // the user can set a header or append the first
    // bytes of the response body.
    HTTP_SERVER_CONN_WAIT_HEADER,

    // A request is buffered and some bytes were appended
    // to the response. Now the user can either append more
    // bytes or send out the response.
    HTTP_SERVER_CONN_WAIT_BODY,

    // A response has been produced and it's being flushed.
    HTTP_SERVER_CONN_FLUSHING,

} HTTP_ServerConnState;

// This structure represents the HTTP connection to
// a client.
typedef struct {

    // If false, this struct is unused
    HTTP_ServerConnState state;

    // Handle to the socket
    SocketHandle handle;

    // Data received by the client
    ByteQueue input;

    // Data being sent to the client
    ByteQueue output;

    // Generation counter. This is used to invalidate
    // response builders that refer to this connection.
    uint16_t gen;

    // This is set during the WAIT_XXX states or
    // the FLUSHING state. When the connection
    // completes flushing and no more bytes are
    // in the output buffer, it frees the connection
    // instead of turning it back to BUFFERING.
    bool closing;

    // When the state is WAIT_STATUS, WAIT_HEADER,
    // or WAIT_BODY, this contains the parsed version
    // of the buffered request.
    HTTP_Request request;

    // Length of the buffered request when the request
    // field is valid.
    int request_len;

    // Offset of the first response byte in the output
    // buffer. This is useful when the user wants to
    // undo the response it's building and start from
    // scratch.
    ByteQueueOffset response_offset;

    // When the first byte of the response content is
    // written, before it are prepended special headers,
    // including Content-Length and Connection. This
    // offset points to the first byte that comes after
    // the string "Content-Length: ".
    ByteQueueOffset content_length_value_offset;

    // Similarly to the previous field, this one points
    // to the first byte of the body. This allows calculating
    // the length of the response content byte subtracting
    // it from the offset reached when the response is marked
    // as done.
    ByteQueueOffset content_length_offset;
} HTTP_ServerConn;

typedef struct {

    // Size limit of the input and output buffer of each
    // connection.
    uint32_t input_buffer_limit;
    uint32_t output_buffer_limit;

    bool trace_bytes;
    bool reuse_addr;
    int backlog;

    // Array of connections. The counter contains the
    // number of structs such that state=FREE.
    int num_conns;
    HTTP_ServerConn conns[HTTP_SERVER_CAPACITY];

    // Queue of indices referring to connections that
    // are in the WAIT_STATUS state.
    int num_ready;
    int ready_head;
    int ready[HTTP_SERVER_CAPACITY];

    // Asynchronous TCP and TLS socket abstraction
    SocketManager sockets;

    // The server object doesn't interact with this
    // field directly, it just initializes the socket
    // manager with a pointer to it. This allows
    // allocating the exact number of sockets we
    // will need.
    Socket socket_pool[HTTP_SERVER_CAPACITY];

} HTTP_Server;

// Initialize the HTTP server object. By default, it won't
// listen for connections. You need to call
//
//   http_server_listen_tcp
//   http_server_listen_tls
//
// to listen for connection. Note that you can have a
// single server listening for HTTP and HTTPS requests
// by calling both.
int http_server_init(HTTP_Server *server);

// Release resources associated to the server.
void http_server_free(HTTP_Server *server);

// Set input and output buffer size limit for any
// given connection. The default value is 1MB
void http_server_set_input_limit(HTTP_Server *server, uint32_t limit);
void http_server_set_output_limit(HTTP_Server *server, uint32_t limit);

// TODO: Comment
void http_server_set_trace_bytes(HTTP_Server *server, bool value);

// TODO: Comment
void http_server_set_reuse_addr(HTTP_Server *server, bool reuse);

// TODO: comment
void http_server_set_backlog(HTTP_Server *server, int backlog);

// Enable listening for plain HTTP requests at the
// specified interface.
int http_server_listen_tcp(HTTP_Server *server,
    HTTP_String addr, Port port);

// Enable listening for HTTPS requests at the specified
// interfact, using the specified certificate and key
// to verify the connection.
int http_server_listen_tls(HTTP_Server *server, HTTP_String addr, Port port,
    HTTP_String cert_file_name, HTTP_String key_file_name);

// Add the certificate for an additional domain when
// the server is listening for HTTPS requests.
int http_server_add_certificate(HTTP_Server *server,
    HTTP_String domain, HTTP_String cert_file, HTTP_String key_file);

// When a thread is blocked waiting for server events,
// other threads can call this function to wake it up.
int http_server_wakeup(HTTP_Server *server);

// Resets the event register with the list of descriptors
// the server wants monitored.
void http_server_register_events(HTTP_Server *server,
    EventRegister *reg);

// The caller has waited for poll() to return and some
// I/O events to be triggered, so now the HTTP server
// can continue its buffering and flushing operations.
void http_server_process_events(HTTP_Server *server,
    EventRegister reg);

typedef struct {
    HTTP_Server *server;
    uint16_t     index;
    uint16_t     gen;
} HTTP_ResponseBuilder;

// After some I/O events were processes, some requests
// may be availabe. This function returns one of the
// buffered requests. If a request was available, true
// is returned. If no more are avaiable, false is returned.
// Note that It's possible to get multiple requests to
// respond in batches.
// For each request returned by this function, the user
// must build a response using the response builder API.
bool http_server_next_request(HTTP_Server *server,
    HTTP_Request **request, HTTP_ResponseBuilder *builder);

// TODO: comment
void http_server_wait_request(HTTP_Server *server,
    HTTP_Request **request, HTTP_ResponseBuilder *builder);

// This function is called to set the status code of
// a request's response. If this function is called
// after the other response builder functions, it will
// reset the response and set a new status.
void http_response_builder_status(HTTP_ResponseBuilder builder, int status);

// Append a header to the response. This can only be
// used after having set the status and before appending
// to the body.
void http_response_builder_header(HTTP_ResponseBuilder builder, HTTP_String str);

// Append some bytes to the response's body
void http_response_builder_body(HTTP_ResponseBuilder builder, HTTP_String str);

// TODO: comment
void  http_response_builder_body_cap(HTTP_ResponseBuilder builder, int cap);
char *http_response_builder_body_buf(HTTP_ResponseBuilder builder, int *cap);
void  http_response_builder_body_ack(HTTP_ResponseBuilder builder, int num);

// Mark the response as complete. This will invalidate
// the response builder handle.
void http_response_builder_send(HTTP_ResponseBuilder builder);

////////////////////////////////////////////////////////////////////////////////////////
// Copyright 2025 Francesco Cozzuto
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom
// the Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall
// be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
////////////////////////////////////////////////////////////////////////////////////////
#endif // HTTP_INCLUDED
