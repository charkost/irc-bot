#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <assert.h>
#include "socket.h"
#include "helper.h"

static int bytes_read;
static char buffer[IRCLEN];
static char *buf_ptr;


BIO *sock_connect(const char *address, const char *port) {

	SSL *ssl;
	SSL_CTX *ctx;
	BIO *SSLbio = NULL;
	X509 *cert;
	X509_NAME *name;
	char host[ADDRLEN + PORTLEN + 1], common_name[512];

	SSL_library_init();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(SSLv23_client_method());
	if (ctx == NULL) {
		fprintf(stderr, "SSL_CTX creation failed\n");
		goto cleanup;
	}

	if (SSL_CTX_load_verify_locations(ctx, SSLSTORE, NULL) == 0) {
		fprintf(stderr, "Error loading trust store\n");
		goto cleanup;
	}

	SSLbio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(SSLbio, &ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	snprintf(host, sizeof(host), "%s:%s", address, port);
	BIO_set_conn_hostname(SSLbio, host);

	if (BIO_do_connect(SSLbio) <= 0) {
	   fprintf(stderr, "Error connecting to server\n");
	   goto cleanup;
	}

	if (BIO_do_handshake(SSLbio) <= 0) {
	   fprintf(stderr, "Error establishing SSL connection\n");
	   goto cleanup;
	}

	if (SSL_get_verify_result(ssl) == X509_V_OK)
		cert = SSL_get_peer_certificate(ssl);
	else {
		fprintf(stderr, "Error verifying SSL certificate\n");
		goto cleanup;
	}

	name = X509_get_subject_name(cert);
	X509_NAME_get_text_by_NID(name, NID_commonName, common_name, 512);

	// if (strcmp(common_name, address) != 0) {
	// 	fprintf(stderr, "Common name didn't match hostname\n");
	// 	goto cleanup;
	// }

	return SSLbio;

cleanup:
	ERR_print_errors_fp(stderr);
	ERR_free_strings();
	SSL_CTX_free(ctx);
	BIO_free_all(SSLbio);
	return NULL;
}

ssize_t sock_write(BIO *sock, const char *buf, size_t len) {

	ssize_t n_sent;
	size_t n_left;
	const char *buf_marker;

	assert(len <= strlen(buf) && "Write length is bigger than buffer size");
	n_left = len;
	buf_marker = buf;

	while (n_left > 0) {
		n_sent = BIO_write(sock, buf_marker, n_left);
		if (n_sent <= 0 && BIO_should_retry(sock)) { // Interrupted by signal, retry
			n_sent = 0;
			continue;
		}
		else if (n_sent <= 0) {
			perror("write");
			return -1;
		}
		n_left -= n_sent;
		buf_marker += n_sent; // Advance buffer pointer to the next unsent bytes
	}
	return len;
}

#ifdef TEST
	ssize_t sock_readbyte(BIO *sock, char *byte)
#else
	static ssize_t sock_readbyte(BIO *sock, char *byte)
#endif
{
	// Stores the character in byte. Returns -1 for fail, 0 if connection is closed or 1 for success
	while (bytes_read <= 0) {
		bytes_read = BIO_read(sock, buffer, IRCLEN);
		if (bytes_read < 0 && BIO_should_retry(sock)) { // Interrupted by signal, retry
			bytes_read = 0;
			continue;
		}
		else if (bytes_read < 0) {
			perror("read");
			return -1;
		}
		else if (bytes_read == 0) // Connection closed
			return 0;

		buf_ptr = buffer;
	}
	bytes_read--;
	*byte = *buf_ptr++;

	return 1;
}

ssize_t sock_readline(BIO *sock, char *line_buf, size_t len) {

	size_t n_read = 0;
	ssize_t n;
	char byte;

	while (n_read++ <= len) {
		n = sock_readbyte(sock, &byte);
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
