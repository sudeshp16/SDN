#ifndef __TLS_H__
#define __TLS_H__

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <pthread.h>
#include <openssl/rand.h>
#include <sdn_transport.h>


typedef union Address
{
		struct sockaddr_storage ss;
		struct sockaddr_in s4;
		struct sockaddr_in6 s6;
}Address;

typedef struct SDNSSL
{
	/*ctx Should  only be freed on Application Exit and ctx would be global*/
    int server_fd;
    int client_fd;
	int listen_exit_flag;
	struct sockaddr_in server_address;
	struct sockaddr_in6 server_address6;
    SSL_CTX *ctx;
	pthread_mutex_t * mutex;
	TRANSPORT_MODE mode;
	SERVICEMODE service_mode;
	//Temporary adding for client bio 
	BIO * client_bio;
    SSL_CTX * (*TLS_TRANSPORT_INIT)(pthread_mutex_t **mutex, char * pcCertificate, char *pcPrivate_key, char *pcsSSL_version, char * pcCipherlist, SERVICEMODE mode);
    void (*SHUTDOWN_TLS_SERVER)(SSL_CTX *ctx, pthread_mutex_t **mutex);
	void * (*serverHandleThread)(void *);
	void * (*clientHandleThread)(void *);
    int (*TLS_SERVER_LISTEN) (struct SDNSSL *this, SSL_CTX *ctx, int iSocketFD);
    int (*TLS_CLIENT_CONNECT)(struct SDNSSL *this, Address server_address);
}SDNSSL;

typedef struct SSL_THREAD_DATA
{
    int server_fd;
    int client_fd;
	int tun_fd;
    SSL_CTX *ctx;
	pthread_mutex_t * mutex;
    SSL *ssl;
    BIO *bio;
    BIO *r_bio;
    BIO *w_bio;
	Address server_addr;
	Address client_addr;
	int timeout;
	struct bio_dgram_sctp_sndinfo sinfo;
    struct bio_dgram_sctp_rcvinfo rinfo;
}SSL_THREAD_DATA;

SDNSSL *init_tls(SDNSSL * this, char * pcCertificate, char *pcPrivate_key, char *pcsSSL_version, char * pcCipherlist);
int tls_listen_loop(SDNSSL *this);
int tls_client_connect(SDNSSL *this, int address_family, char * pcIP, uint16_t port);
void destroy_tls(SDNSSL *this);

#define COOKIE_SECRET_LENGTH 16
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];


#endif	// __TLS_H__
