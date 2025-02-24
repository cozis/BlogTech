#include <stdio.h> // printf

#ifdef _WIN32
#include <winsock2.h>
#define SOCKET_TYPE SOCKET
#define INVALID_SOCKET_VALUE INVALID_SOCKET
#define CLOSE_SOCKET closesocket
#else
#include <unistd.h> // close
#include <arpa/inet.h> // socket, htons, inet_addr, sockaddr_in, bind, listen, accept, recv, send
#define SOCKET_TYPE int
#define INVALID_SOCKET_VALUE -1
#define CLOSE_SOCKET close
#endif

int main()
{
#ifdef _WIN32
	WSADATA wsaData;
	int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err != 0) {
		printf("WSAStartup failed\n");
		return -1;
	}
#endif

	// Create the listening socket
	SOCKET_TYPE listen_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_socket == INVALID_SOCKET_VALUE) {
		printf("socket failed\n");
		return -1;
	}

	struct sockaddr_in bind_buffer;
	bind_buffer.sin_family = AF_INET;
	bind_buffer.sin_port = htons(8080);
	bind_buffer.sin_addr.s_addr = inet_addr("127.0.0.1");

	if (bind(listen_socket, (struct sockaddr*) &bind_buffer, sizeof(bind_buffer))) {
		printf("bind failed\n");
		return -1;
	}

	if (listen(listen_socket, 32)) {
		printf("listen failed\n");
		return -1;
	}

	while (1) {
		SOCKET_TYPE client_socket = accept(listen_socket, NULL, NULL);
		if (client_socket == INVALID_SOCKET_VALUE) {
			printf("accept failed\n");
			continue;
		}

		char request_buffer[4096];
		int len = recv(client_socket, request_buffer, sizeof(request_buffer), 0);
		if (len < 0) {
			printf("recv failed\n");
			CLOSE_SOCKET(client_socket);
			continue;
		}

		// We ignore the request contents for now and always
		// respond with the same message
		char response_buffer[] =
			"HTTP/1.0 200 OK\r\n"
			"Content-Length: 13\r\n"
			"Content-Type: text/plain\r\n"
			"\r\n"
			"Hello, world!";
		send(client_socket, response_buffer, sizeof(response_buffer), 0);

		CLOSE_SOCKET(client_socket);
	}
	// This point will never be reached
}
