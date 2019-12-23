#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <pthread.h>
#include <main.h>
#include <sdn_sctp.h>
#include <openssl/rand.h>

#include <dtls_encrypt.h>



/** Returns Thread id , required for OpenSSL*/
static unsigned long id_function(void) 
{
	return pthread_self();
}

static pthread_mutex_t* mutex_buf = NULL;

static void locking_function(int mode, int n, const char *file, int line) 
{
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&mutex_buf[n]);
    else
        pthread_mutex_unlock(&mutex_buf[n]);
}

int Crypto_Thread_init(pthread_mutex_t **mutex_buf)
{
	int i = 0;
	if (!mutex_buf)
		return 0;
 	*mutex_buf = (pthread_mutex_t*) malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	if (!*mutex_buf)
        return 0;
    for (i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_init(mutex_buf[i], NULL);
    CRYPTO_set_id_callback(id_function);
    CRYPTO_set_locking_callback(locking_function);
    return 1;
}

int  Crypto_Thread_destroy(pthread_mutex_t **mutex)
{
	int i = 0;
	if (!mutex)
		return 0;
    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
    	pthread_mutex_destroy(((*mutex) + i));
    free(*mutex);
    *mutex = NULL;
    return 1;
}


int dtls_verify_callback(int ok, X509_STORE_CTX *ctx)
{
	// Always Returns 1 for Client Certificate Verification
	return 1;
}
int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;
	/* Initialize a random secret */
	if (!cookie_initialized)
	{
		if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
		{
			printf("error setting random cookie secret\n");
			return 0;
		}
		cookie_initialized = 1;
	}

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
	{
		printf("out of memory\n");
		return 0;
	}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
			       &peer.s4.sin_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(peer.s4.sin_port),
			       &peer.s4.sin_addr,
			       sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
			       &peer.s6.sin6_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s6.sin6_addr,
			       sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
	     (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

int verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len)
{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* If secret isn't initialized yet, the cookie can't be valid */
	if (!cookie_initialized)
		return 0;

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
			       &peer.s4.sin_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s4.sin_addr,
			       sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
			       &peer.s6.sin6_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s6.sin6_addr,
			       sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
	     (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
		return 1;

	return 0;
}




int handle_socket_error() {
	switch (errno) {
		case EINTR:
			/* Interrupted system call.
			 * Just ignore.
			 */
			printf("Interrupted system call!\n");
			return 1;
		case EBADF:
			/* Invalid socket.
			 * Must close connection.
			 */
			printf("Invalid socket!\n");
			return 0;
			break;
#ifdef EHOSTDOWN
		case EHOSTDOWN:
			/* Host is down.
			 * Just ignore, might be an attacker
			 * sending fake ICMP messages.
			 */
			printf("Host is down!\n");
			return 1;
#endif
#ifdef ECONNRESET
		case ECONNRESET:
			/* Connection reset by peer.
			 * Just ignore, might be an attacker
			 * sending fake ICMP messages.
			 */
			printf("Connection reset by peer!\n");
			return 1;
#endif
		case ENOMEM:
			/* Out of memory.
			 * Must close connection.
			 */
			printf("Out of memory!\n");
			return 0;
			break;
		case EACCES:
			/* Permission denied.
			 * Just ignore, we might be blocked
			 * by some firewall policy. Try again
			 * and hope for the best.
			 */
			printf("Permission denied!\n");
			return 1;
			break;
		default:
			/* Something unexpected happened */
			printf("Unexpected error! (errno = %d)\n", errno);
			return 0;
			break;
	}
	return 0;
}



int InitSSLLibrary(pthread_mutex_t **mutex)
{
	int iRet = 0;
    SSL_load_error_strings();
	SSL_library_init(); /* initialize library */
   	OpenSSL_add_ssl_algorithms();
	if (mutex)
	{
		iRet = Crypto_Thread_init(mutex);
		if (iRet <= 0)
		{
			printf("Failed To initialize threads For Server \n");
			return 0;
		}
	}
	return 1;
}



SSL_CTX * InitSSLServer(pthread_mutex_t **mutex, char * pcCertificate, char *pcPrivate_key, TRANSPORT_MODE tmode, char *pcsSSL_version, char * pcCipherlist)
{
	int iRet = 0;
	SSL_CTX *ctx = NULL;
	iRet = InitSSLLibrary(mutex);
	if (tmode = TRANSPORT_MODE_UDP){
    	ctx = SSL_CTX_new(DTLSv1_server_method());
	}
	else{
    	ctx = SSL_CTX_new(TLSv1_2_server_method());
	}
	if (ctx == NULL){
		printf("Failed to initialize ctx\n");
		return NULL;
	}
    if ((iRet = SSL_CTX_set_cipher_list(ctx, pcCipherlist)) == 0){
		printf("Invalid Cipher List\n");
		SSL_CTX_free(ctx);
		return NULL;
	}
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	if (!SSL_CTX_use_certificate_file(ctx, pcCertificate, SSL_FILETYPE_PEM)){
    	printf("\nERROR: no certificate found!");
		SSL_CTX_free(ctx);
		return NULL;
	}
    if (!SSL_CTX_use_PrivateKey_file(ctx, pcPrivate_key, SSL_FILETYPE_PEM)){
        printf("\nERROR: no private key found!");
		SSL_CTX_free(ctx);
		return NULL;
	}
    if (!SSL_CTX_check_private_key (ctx)){
        printf("\nERROR: invalid private key!");
		SSL_CTX_free(ctx);
		return NULL;
	}
/*
    SSL_CTX_set_verify_depth (ctx, 2);
    SSL_CTX_set_read_ahead(ctx, 1);
*/
    if (TRANSPORT_MODE_UDP == tmode)
	{
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
    	SSL_CTX_set_read_ahead(ctx, 1);
    	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    	SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
	}
	else if (TRANSPORT_MODE_SCTP == tmode)
	{

	}
	return ctx;
}




void *UDPSSLServerThread(void *arg)
{
	int tun_fd =  -1, sock_fd = -1;
	int iAddressFamily = AF_UNSPEC;
	char read_buffer[65535];
	char write_buffer[65535];
	struct SSLThreadArg * args = NULL;
	if (!arg)
		pthread_exit(NULL);
	arg = (struct SSLThreadArg *)arg;
	SSL *ssl = args->ssl;
	BIO *bio = args->bio;
	sock_fd = args->server_fd;
	BIO_ADDR * cli_addr = args->cli_addr;
	pthread_dettach(pthread_self());
	if (args->iAddressFamily == AF_INET)
	{
		args->client_fd = socket(AF_INET, SOCK_DGRAM, 0);
	}
	else
	{
		args->client_fd = socket(AF_INET6, SOCK_DGRAM, 0);
	}


	
}

int ServerHandleLoop(int iSocketfd , SSL_CTX * ctx, TRANSPORT_MODE tmode, int iAddrFamily)
{
	SSL *ssl = NULL;
	BIO *bio = NULL;
	int iRet = 0;
	if (!ctx || iSocketfd < 0)
		return  -1 ;
	ssl = SSL_new(ctx);
	if (ssl == NULL) {
        printf("\nERROR: Unable to Initialize SSL !");
        SSL_CTX_free(ctx);
        return -2;
    }
	if (tmode == TRANSPORT_MODE_UDP)
	{
		bio = BIO_new_dgram(iSocketfd, BIO_NOCLOSE);
		if (bio == NULL)
		{
			SSL_free(ssl);
			printf("ERROR: Failed To Create SSL Bio\n");
			return -3;
		}
		else
		{
			struct timeval timeout;
			timeout.tv_sec = 10;
        	timeout.tv_usec = 0;
			BIO_ADDR client_addr;
        	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
			SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
			SSL_set_bio(ssl, bio, bio);
			while (DTLSv1_listen(ssl, &client_addr) <= 0);
			SSLThreadArg arg;
			arg.ssl = ssl;
			arg.bio = bio;
			arg.server_fd = iSocketfd;
			/*Create Thread To handle communction to be implemented*/
			return 1;
		}
	}
	else if (tmode == TRANSPORT_MODE_TCP)
	{
		iRet = SSL_set_fd(ssl, iSocketfd);
		if (iRet == 0)
		{
			printf("ERROR: Failed to Set FD\n");
			return -4;
		}
		iRet = SSL_accept(ssl);
		if (iRet == 0)
		{
			printf("ERROR: Failed to Accept Establish SSL Handshake\n");
			return -5;
		}
		/*Create Thread To handle communction to be implemented*/
		return 1;
	}
	else if (tmode == TRANSPORT_MODE_SCTP)
	{
		
	}
	return 1;
}


SSL_CTX * InitSSLClient(char * pcCertificate, char *pcPrivate_key, TRANSPORT_MODE tmode, char *pcsSSL_version, char * pcCipherlist)
{
	int iRet = 0;
	SSL_CTX *ctx = NULL;
	iRet = InitSSLLibrary(NULL);
	if (iRet == 0)
		return NULL;
	if (tmode = TRANSPORT_MODE_UDP)
	{
    	ctx = SSL_CTX_new(DTLSv1_client_method());
	}
	else
	{
    	ctx = SSL_CTX_new(TLSv1_2_client_method());
	}
	if (ctx == NULL){
		printf("Failed to initialize ctx\n");
		return NULL;
	}
    if ((iRet = SSL_CTX_set_cipher_list(ctx, pcCipherlist)) == 0){
		printf("Invalid Cipher List\n");
		SSL_CTX_free(ctx);
		return NULL;
	}
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	if (!SSL_CTX_use_certificate_file(ctx, pcCertificate, SSL_FILETYPE_PEM)){
    	printf("\nERROR: no certificate found!");
		SSL_CTX_free(ctx);
		return NULL;
	}
    if (!SSL_CTX_use_PrivateKey_file(ctx, pcPrivate_key, SSL_FILETYPE_PEM)){
        printf("\nERROR: no private key found!");
		SSL_CTX_free(ctx);
		return NULL;
	}
    if (!SSL_CTX_check_private_key (ctx)){
        printf("\nERROR: invalid private key!");
		SSL_CTX_free(ctx);
		return NULL;
	}
/*
    SSL_CTX_set_verify_depth (ctx, 2);
    SSL_CTX_set_read_ahead(ctx, 1);
*/
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
    if (TRANSPORT_MODE_UDP == tmode)
	{
    	SSL_CTX_set_read_ahead(ctx, 1);
    	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    	SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
	}
	else if (TRANSPORT_MODE_SCTP == tmode)
	{

	}
	return ctx;
}



void SSLClientHandleLoop(int iSocketfd , SSL_CTX * ctx, TRANSPORT_MODE tmode, int tun_fd)
{
	SSL *ssl = NULL;
	BIO *bio = NULL;
	int iRet = 0;
	if (!ctx || iSocketfd < 0)
		return;
	ssl = SSL_new(ctx);
	if (ssl == NULL) {
        printf("\nERROR: Unable to Initialize SSL !");
        SSL_CTX_free(ctx);
        return;
    }
	if (tmode == TRANSPORT_MODE_UDP)
	{
		bio = BIO_new_dgram(iSocketfd, BIO_NOCLOSE);
		if (bio == NULL)
		{
			SSL_free(ssl);
			SSL_CTX_free(ctx);
			printf("ERROR: Failed To Create SSL UDP  Bio\n");
		}
		else
		{
			struct timeval timeout;
			timeout.tv_sec = 10;
        	timeout.tv_usec = 0;
        	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
			SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
			SSL_set_bio(ssl, bio, bio);
			
		}
	}
	else if (tmode == TRANSPORT_MODE_TCP)
	{
		iRet = SSL_set_fd(ssl, iSocketfd);
		if (iRet == 0)
		{
			printf("ERROR: Failed to Set FD\n");
			return;
		}
		iRet = SSL_connect(ssl);
		if (iRet == 0)
		{
			printf("ERROR: Failed to Accept Establish SSL Handshake\n");
			return;
		}
	}
	else if (tmode == TRANSPORT_MODE_SCTP)
	{
		bio = BIO_new_dgram_sctp(iSocketfd, BIO_CLOSE);
		if (bio == NULL)
		{
			SSL_free(ssl);
			SSL_CTX_free(ctx);
			printf("ERROR: Failed To Create SSL SCTP  Bio\n");
		}
		else
		{
			
		}
	}
}

