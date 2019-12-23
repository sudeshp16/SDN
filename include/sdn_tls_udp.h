#ifndef __SDN_TLS_UDP_H__
#define __SDN_TLS_UDP_H__

/* Includes */
#include <sdn_tls.h>
#include <sdn_interface_ops.h>
#include <sdn_tun.h>


/** Function Declarations */
int Crypto_Thread_init(pthread_mutex_t **mutex_buf);
int  Crypto_Thread_destroy(pthread_mutex_t **mutex);
int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
int verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len);
int dtls_verify_callback(int ok, X509_STORE_CTX *ctx);
SSL_CTX * InitUDPSSL(pthread_mutex_t **mutex, char * pcCertificate, char *pcPrivate_key, char *pcsSSL_version, char * pcCipherlist, SERVICEMODE mode);
void SHUTDOWN_UDP_TLS_SERVER(SSL_CTX *ctx, pthread_mutex_t **mutex);
int UDP_TLS_SERVER_LISTEN(SDNSSL *this, SSL_CTX *ctx, int iSocketFD);
int TLS_UDP_CLIENT_CONNECT(struct SDNSSL *this, Address server_address);
void * HandleUDPServerClient(void * args);
void * HandleUDPClientServer(void *arg);


#endif	//__SDN_TLS_UDP_H__
