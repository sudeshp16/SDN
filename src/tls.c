#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <pthread.h>
#include <openssl/rand.h>


typedef struct SDNSSL
{
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	BIO *r_bio;
	BIO *w_bio;
	int server_fd;
	int client_fd;
	SSL_CTX * (*TLS_TRANSPORT_INIT)(pthread_mutex_t **mutex, char * pcCertificate, char *pcPrivate_key, char *pcsSSL_version, char * pcCipherlist);
	int (*TLS_SERVER_LISTEN)(SSL_CTX *ctx, int iSocketFD , void * (*fpServerHandleLoopFn)(void * arg));
	SHUTDOWN_TLS_SERVER(SSL_CTX *ctx);
	int (*TLS_CLIENT_CONNECT)(SSL_CTX *ctx, int iSocketFD , void * (*fpClientCommLoop)(void * arg));	
}SDNSSL;


 
