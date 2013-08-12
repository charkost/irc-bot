#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>
#include "socket.h"
#include "helper.h"

static int bytes_read;
static char buffer[IRCLEN];
static char *buf_ptr;


int sock_connect(const char *address, const char *port) {

	int sock, ret_value;
	struct addrinfo addr_filter, *addr_holder, *addr_iterator;

	// Create filter for getaddrinfo()
	memset(&addr_filter, 0, sizeof(addr_filter));
	addr_filter.ai_family   = AF_UNSPEC; 	   // IPv4 or IPv6
	addr_filter.ai_socktype = SOCK_STREAM; 	   // Stream socket
	addr_filter.ai_protocol = IPPROTO_TCP;	   // TCP protocol

	// Don't try to resolve service -> port, since we already provide it in numeric form
	addr_filter.ai_flags   |= AI_NUMERICSERV;

	// Return addresses according to the filter criteria
	ret_value = getaddrinfo(address, port, &addr_filter, &addr_holder);
	if (ret_value != 0)
		exit_msg("getaddrinfo: %s", gai_strerror(ret_value));

	sock = -1;
	for (addr_iterator = addr_holder; addr_iterator != NULL; addr_iterator = addr_holder->ai_next) {

		// Create TCP socket
		sock = socket(addr_iterator->ai_family, addr_iterator->ai_socktype, addr_iterator->ai_protocol);
		if (sock < 0)
			continue; // Failed, try next address

		ret_value = connect(sock, addr_iterator->ai_addr, addr_iterator->ai_addrlen);
		if (ret_value == 0)
			break; // Success

		close(sock); // Cleanup and try next address
		sock = -1;
	}
	freeaddrinfo(addr_holder);
	return sock;
}

ssize_t sock_write(SSL *ssl_handle, const char *buf, size_t len) {

	size_t ret;

	assert(len <= strlen(buf) && "Write length is bigger than buffer size");

	ret = SSL_write(ssl_handle, buf, len);
	if (ret <= 0) {
		perror("write");
		return -1;
	}
	return ret;
}

#ifdef TEST
	ssize_t sock_readbyte(SSL *ssl_handle, char *byte)
#else
	static ssize_t sock_readbyte(SSL *ssl_handle, char *byte)
#endif
{
	// Stores the character in byte. Returns <=0 for fail, >0 for success
	while (bytes_read <= 0) {
		bytes_read = SSL_read(ssl_handle, buffer, IRCLEN);
		if (bytes_read <= 0 && SSL_get_error(ssl_handle, bytes_read) == SSL_ERROR_ZERO_RETURN) { // Connection closed
			return 0;
		}
		else if (bytes_read <= 0) {
			perror("read");
			return -1;
		}
		buf_ptr = buffer;
	}
	bytes_read--;
	*byte = *buf_ptr++;

	return 1;
}

ssize_t sock_readline(SSL *ssl_handle, char *line_buf, size_t len) {

	size_t n_read = 0;
	ssize_t n;
	char byte;

	while (n_read++ <= len) {
		n = sock_readbyte(ssl_handle, &byte);
		if (n < 0)
			return -1;
		else if (n == 0) { // Connection closed, return bytes read so far
			*line_buf = '\0';
			return n_read - 1;
		}
		*line_buf++ = byte;
		if (byte == '\n' && *(line_buf - 2) == '\r')
			break; // Message complete, we found irc protocol terminators
	}
	*line_buf = '\0';

	return n_read;
}
