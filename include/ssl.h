#ifndef SSL_H
#define SSL_H

#include <sys/types.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Create a new context for the SSL struct
// Returns a pointer to the context
SSL_CTX *ssl_new_context(void);

// Create SSL struct and link it with the given socket
// Returns a pointer(handler) to the SSL struct which will be used for SSL_write and SSL_read functions
SSL *ssl_new_handle(SSL_CTX *ssl_context, int sock);

// SSL struct clean up
void ssl_close(SSL_CTX *ssl_context, SSL *ssl_handle);

#endif
