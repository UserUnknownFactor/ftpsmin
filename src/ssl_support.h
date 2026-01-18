//------------------------------------------------------------------------------------
// SSL/TLS Support Header
//------------------------------------------------------------------------------------
#ifndef SSL_SUPPORT_H
#define SSL_SUPPORT_H

#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

// Initialize SSL library and create context
BOOL SSL_Initialize(const char *certFile, const char *keyFile);

// Cleanup SSL library
void SSL_Cleanup(void);

// Create SSL connection for a socket (server-side accept)
SSL* SSL_CreateConnection(int socket);

// Free SSL connection
void SSL_FreeConnection(SSL *ssl);

// Get SSL error string
const char* SSL_GetErrorString(SSL *ssl, int ret);

#endif // SSL_SUPPORT_H