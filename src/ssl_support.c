//------------------------------------------------------------------------------------
// SSL/TLS Support Implementation
//------------------------------------------------------------------------------------
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include "ssl_support.h"

static SSL_CTX *g_SSLContext = NULL;
static CRITICAL_SECTION *g_SSLLocks = NULL;
static int g_NumLocks = 0;

//------------------------------------------------------------------------------------
// OpenSSL threading callback (for older OpenSSL versions)
//------------------------------------------------------------------------------------
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void SSLLockingCallback(int mode, int n, const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
        EnterCriticalSection(&g_SSLLocks[n]);
    } else {
        LeaveCriticalSection(&g_SSLLocks[n]);
    }
}

static unsigned long SSLThreadIdCallback(void)
{
    return (unsigned long)GetCurrentThreadId();
}

static void InitSSLLocks(void)
{
    int i;
    g_NumLocks = CRYPTO_num_locks();
    g_SSLLocks = (CRITICAL_SECTION*)malloc(g_NumLocks * sizeof(CRITICAL_SECTION));
    for (i = 0; i < g_NumLocks; i++) {
        InitializeCriticalSection(&g_SSLLocks[i]);
    }
    CRYPTO_set_locking_callback(SSLLockingCallback);
    CRYPTO_set_id_callback(SSLThreadIdCallback);
}

static void CleanupSSLLocks(void)
{
    int i;
    if (g_SSLLocks) {
        CRYPTO_set_locking_callback(NULL);
        CRYPTO_set_id_callback(NULL);
        for (i = 0; i < g_NumLocks; i++) {
            DeleteCriticalSection(&g_SSLLocks[i]);
        }
        free(g_SSLLocks);
        g_SSLLocks = NULL;
    }
}
#else
static void InitSSLLocks(void) { }
static void CleanupSSLLocks(void) { }
#endif

//------------------------------------------------------------------------------------
// Initialize SSL library and create context
//------------------------------------------------------------------------------------
BOOL SSL_Initialize(const char *certFile, const char *keyFile)
{
    const SSL_METHOD *method;
    
    // Initialize OpenSSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#else
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif
    
    // Initialize threading support
    InitSSLLocks();
    
    // Create SSL context using flexible method
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    method = SSLv23_server_method();
#else
    method = TLS_server_method();
#endif
    
    g_SSLContext = SSL_CTX_new(method);
    if (!g_SSLContext) {
        fprintf(stderr, "Failed to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return FALSE;
    }
    
    // Set minimum TLS version to 1.2
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_CTX_set_min_proto_version(g_SSLContext, TLS1_2_VERSION);
#else
    SSL_CTX_set_options(g_SSLContext, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
#endif
    
    // Set other options
    SSL_CTX_set_options(g_SSLContext, SSL_OP_SINGLE_DH_USE);
    SSL_CTX_set_options(g_SSLContext, SSL_OP_NO_COMPRESSION);
    
    // Load certificate
    if (SSL_CTX_use_certificate_file(g_SSLContext, certFile, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load certificate file: %s\n", certFile);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(g_SSLContext);
        g_SSLContext = NULL;
        return FALSE;
    }
    
    // Load private key
    if (SSL_CTX_use_PrivateKey_file(g_SSLContext, keyFile, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load private key file: %s\n", keyFile);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(g_SSLContext);
        g_SSLContext = NULL;
        return FALSE;
    }
    
    // Verify private key matches certificate
    if (!SSL_CTX_check_private_key(g_SSLContext)) {
        fprintf(stderr, "Private key does not match certificate\n");
        SSL_CTX_free(g_SSLContext);
        g_SSLContext = NULL;
        return FALSE;
    }
    
    // Set cipher list (prefer strong ciphers)
    if (!SSL_CTX_set_cipher_list(g_SSLContext, 
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-SHA384:"
        "ECDHE-RSA-AES256-SHA384:"
        "ECDHE-ECDSA-AES128-SHA256:"
        "ECDHE-RSA-AES128-SHA256:"
        "AES256-GCM-SHA384:"
        "AES128-GCM-SHA256:"
        "AES256-SHA256:"
        "AES128-SHA256")) {
        fprintf(stderr, "Warning: Failed to set preferred cipher list\n");
    }
    
    // Enable session caching
    SSL_CTX_set_session_cache_mode(g_SSLContext, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_session_id_context(g_SSLContext, (unsigned char*)"ftpsmin", 7);
    
    return TRUE;
}

//------------------------------------------------------------------------------------
// Cleanup SSL library
//------------------------------------------------------------------------------------
void SSL_Cleanup(void)
{
    if (g_SSLContext) {
        SSL_CTX_free(g_SSLContext);
        g_SSLContext = NULL;
    }
    
    CleanupSSLLocks();
    
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
#endif
}

//------------------------------------------------------------------------------------
// Create SSL connection for a socket
//------------------------------------------------------------------------------------
SSL* SSL_CreateConnection(int socket)
{
    SSL *ssl;
    int ret;
    int retries = 0;
    const int maxRetries = 3;
    
    if (!g_SSLContext) {
        return NULL;
    }
    
    ssl = SSL_new(g_SSLContext);
    if (!ssl) {
        fprintf(stderr, "Failed to create SSL structure\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    if (!SSL_set_fd(ssl, socket)) {
        fprintf(stderr, "Failed to set SSL file descriptor\n");
        SSL_free(ssl);
        return NULL;
    }
    
    // Perform SSL handshake with retries for WANT_READ/WANT_WRITE
    while (retries < maxRetries) {
        ret = SSL_accept(ssl);
        if (ret > 0) {
            // Success
            return ssl;
        }
        
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // Need to retry
            retries++;
            Sleep(100);
            continue;
        }
        
        // Real error
        fprintf(stderr, "SSL handshake failed, error: %d\n", err);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    
    fprintf(stderr, "SSL handshake timed out\n");
    SSL_free(ssl);
    return NULL;
}

//------------------------------------------------------------------------------------
// Free SSL connection
//------------------------------------------------------------------------------------
void SSL_FreeConnection(SSL *ssl)
{
    if (ssl) {
        // Try a clean shutdown, but don't wait too long
        int ret = SSL_shutdown(ssl);
        if (ret == 0) {
            // Need to call again for bidirectional shutdown
            SSL_shutdown(ssl);
        }
        SSL_free(ssl);
    }
}

//------------------------------------------------------------------------------------
// Get SSL error string
//------------------------------------------------------------------------------------
const char* SSL_GetErrorString(SSL *ssl, int ret)
{
    static char buffer[256];
    int err = SSL_get_error(ssl, ret);
    
    switch (err) {
        case SSL_ERROR_NONE:
            return "No error";
        case SSL_ERROR_ZERO_RETURN:
            return "Connection closed";
        case SSL_ERROR_WANT_READ:
            return "Want read";
        case SSL_ERROR_WANT_WRITE:
            return "Want write";
        case SSL_ERROR_WANT_CONNECT:
            return "Want connect";
        case SSL_ERROR_WANT_ACCEPT:
            return "Want accept";
        case SSL_ERROR_WANT_X509_LOOKUP:
            return "Want X509 lookup";
        case SSL_ERROR_SYSCALL:
            snprintf(buffer, sizeof(buffer), "System error: %d", WSAGetLastError());
            return buffer;
        case SSL_ERROR_SSL:
            ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
            return buffer;
        default:
            snprintf(buffer, sizeof(buffer), "Unknown error: %d", err);
            return buffer;
    }
}