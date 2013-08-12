#include <stdio.h>
#include "ssl.h"

SSL_CTX *ssl_new_context(void) {

	SSL_CTX *ssl_context;
	
	// Register the error strings for libcrypto & libssl
	SSL_load_error_strings();
	// Register the available ciphers and digests
	SSL_library_init();

	// New context saying we are a client, and using SSL 2 or 3
	ssl_context = SSL_CTX_new(SSLv23_method());
	if (ssl_context == NULL)
		ERR_print_errors_fp(stderr);

	return ssl_context;
}

SSL *ssl_new_handle(SSL_CTX *ssl_context, int sock) {

	SSL *ssl_handle;
	      
	ssl_handle = SSL_new(ssl_context);
	if (ssl_handle == NULL)
		ERR_print_errors_fp(stderr);

	// Connect the SSL struct to our socket
	if (!SSL_set_fd(ssl_handle, sock))
		ERR_print_errors_fp(stderr);

	// Initiate SSL handshake
	if (SSL_connect(ssl_handle) != 1)
		ERR_print_errors_fp(stderr);

	SSL_set_mode(ssl_handle, SSL_MODE_AUTO_RETRY);

	return ssl_handle;
}

void ssl_close(SSL_CTX *ssl_context, SSL *ssl_handle) {

	if (ssl_handle != NULL) {
		SSL_shutdown(ssl_handle);
		SSL_free(ssl_handle);
	}
	if (ssl_context != NULL)
		SSL_CTX_free (ssl_context);
}
