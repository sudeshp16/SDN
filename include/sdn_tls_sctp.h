#ifndef __SDN_TLS_SCTP_H__
#define __SDN_TLS_SCTP_H__

/* Includes */
#include <sdn_tls.h>
#include <sdn_interface_ops.h>
#include <sdn_tun.h>
#include <netinet/sctp.h>



/** Function Declarations */
int Crypto_Thread_init_sctp(pthread_mutex_t **mutex_buf);
int  Crypto_Thread_destroy_sctp(pthread_mutex_t **mutex);
int dtls_verify_callback_sctp(int ok, X509_STORE_CTX *ctx);
SSL_CTX * InitSCTPSSL(pthread_mutex_t **mutex, char * pcCertificate, char *pcPrivate_key, char *pcsSSL_version, char * pcCipherlist, SERVICEMODE mode);
void SHUTDOWN_SCTP_TLS_SERVER(SSL_CTX *ctx, pthread_mutex_t **mutex);
int SCTP_TLS_SERVER_LISTEN(SDNSSL *this, SSL_CTX *ctx, int iSocketFD);
int TLS_SCTP_CLIENT_CONNECT(struct SDNSSL *this, Address server_address);
void * HandleSCTPServerClient(void * args);
void * HandleSCTPClientServer(void *arg);


#endif	//__SDN_TLS_SCTP_H__
