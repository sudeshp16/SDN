#include <sdn_tls.h>
#include <sdn_tls_udp.h>
#include <sdn_interface_ops.h>
#include <sdn_tun.h>

int cookie_initialized=0;
extern pthread_mutex_t* mutex_buf;

static unsigned long id_function(void)
{
    return pthread_self();
}

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
    if (!(*mutex_buf))
        return 0;
    for (i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_init((*mutex_buf) + i, NULL);
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


int dtls_verify_callback(int ok, X509_STORE_CTX *ctx)
{
	// Always Returns 1 for Client Certificate Verification
	return 1;
}

SSL_CTX * InitUDPSSL(pthread_mutex_t **mutex, char * pcCertificate, char *pcPrivate_key, char *pcsSSL_version, char * pcCipherlist, SERVICEMODE mode)
{

	int iRet = 0;
    SSL_CTX *ctx = NULL;
	SSL_load_error_strings();
    SSL_library_init(); /* initialize library */
    OpenSSL_add_ssl_algorithms();
    if (mutex)
    {
        iRet = Crypto_Thread_init(mutex);
        if (iRet <= 0)
        {
            printf("Failed To initialize threads For Server \n");
            return NULL;
        }
    }
	if (mode == SERVICEMODE_SERVER)
    	ctx = SSL_CTX_new(DTLSv1_server_method());
	else
    	ctx = SSL_CTX_new(DTLSv1_client_method());
		
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
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
    SSL_CTX_set_read_ahead(ctx, 1);
   	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
	return ctx;
}


void SHUTDOWN_UDP_TLS_SERVER(SSL_CTX *ctx, pthread_mutex_t **mutex)
{
	if (mutex)
	{
		Crypto_Thread_destroy(mutex);
	}
	SSL_CTX_free(ctx);
}

int UDP_TLS_SERVER_LISTEN(SDNSSL *this, SSL_CTX *ctx, int iSocketFD)
{
	struct timeval timeout;
	socklen_t len;
	Address server_addr, client_addr;
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	SSL_THREAD_DATA *thread_data = NULL;
	if (!ctx || !iSocketFD)
	{
		printf("Ctx %p or Socket desc %d Failed \n", ctx, iSocketFD);
		return -1;
	}
	len = sizeof(server_addr);
	getsockname(iSocketFD, (struct sockaddr*)&server_addr, &len);
	while (!this->listen_exit_flag)
	{
		pthread_t tid;
		thread_data = (SSL_THREAD_DATA *)malloc(sizeof(SSL_THREAD_DATA));	
		if (!thread_data)
		{
			printf("Not Enough Memory !!!\n");
			return -2;
		}
		thread_data->ctx = ctx;
		thread_data->ssl = SSL_new(ctx);
		thread_data->bio = BIO_new_dgram(iSocketFD, BIO_NOCLOSE);
		thread_data->server_fd = iSocketFD;
    	if (thread_data->bio == NULL)
    	{
       		SSL_free(thread_data->ssl);
       		printf("ERROR: Failed To Create SSL Bio\n");
       		return -3;
    	}
    	else
		{
			BIO_ctrl(thread_data->bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
			SSL_set_bio(thread_data->ssl, thread_data->bio, thread_data->bio);
			SSL_set_options(thread_data->ssl, SSL_OP_COOKIE_EXCHANGE);
			printf("Awaiting for new TLS connection\n");
			while (DTLSv1_listen(thread_data->ssl, &client_addr) <= 0);
		/*
			thread_data->server_addr.s4.sin_family = AF_INET;
			thread_data->server_addr.s4.sin_addr.s_addr = INADDR_ANY;
			thread_data->server_addr.s4.sin_port = htons(9000);
		*/
			memcpy(&thread_data->server_addr, &server_addr, sizeof(struct sockaddr_storage));
			memcpy(&thread_data->client_addr, &client_addr, sizeof(struct sockaddr_storage));
			printf("Got a new TLS connection, will create a new thread\n");
			pthread_create(&tid, NULL, HandleUDPServerClient, (void *)thread_data);	
		
		}
		/*Loop Forever*/
	}
	return 0;
}


void * HandleUDPServerClient(void * args)
{
	int on = 1;
	int off = 0;
	int iRet = 0, activity = -1;
	int tunnel_recvd_bytes = -1;
	int tunnel_written_bytes = -1;
	int ssl_recvd_bytes = -1;
	int ssl_written_bytes = -1;
	long long bytes_sent = 0;
	long long bytes_recvd = 0;
	char tunnel_buffer[65536];
	char SSL_Buffer[65536];
	struct timeval timeout;
	char error_buff[1024];
	char tun_name[20];
	SSL_THREAD_DATA * data = (SSL_THREAD_DATA *)args;
	if (!data)
		pthread_exit(NULL);
	SSL_CTX *ctx = data->ctx;
	SSL *ssl = data->ssl; 	
	fd_set read_fd_set;
	pthread_detach(pthread_self());
	/* Set and activate timeouts */
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	printf("Created a new thread to handle client\n");	
	data->client_fd = socket(data->client_addr.ss.ss_family, SOCK_DGRAM, 0);
	if (data->client_fd < 0) 
	{
		perror("socket");
	}
	setsockopt(data->client_fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
	setsockopt(data->client_fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));
	switch (data->client_addr.ss.ss_family) 
	{
		case AF_INET:
			iRet = bind(data->client_fd, (const struct sockaddr *) &data->server_addr, sizeof(struct sockaddr_in));
			if (iRet < 0)
			{
				perror("Bind address to reconnect Failed");
			}
			iRet = connect(data->client_fd, (struct sockaddr *) &data->client_addr, sizeof(struct sockaddr_in));
			if (iRet < 0)
			{
				perror("Reconnect Failed");
			}
			break;
		case AF_INET6:
			setsockopt(data->client_fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
			bind(data->client_fd, (const struct sockaddr *) &data->server_addr, sizeof(struct sockaddr_in6));
			connect(data->client_fd, (struct sockaddr *) &data->client_addr, sizeof(struct sockaddr_in6));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	/* Set new fd and set BIO to connected */
	BIO_set_fd(SSL_get_rbio(ssl), data->client_fd, BIO_NOCLOSE);
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &data->client_addr.ss);

	/* Finish handshake */
	do { iRet = SSL_accept(ssl); }
	while (iRet == 0);
	if (iRet < 0) {
		perror("SSL_accept");
		printf("%s\n", ERR_error_string(ERR_get_error(), error_buff));
	}
	printf("Accepted SSL Handshake from New Connection\n");
	strncpy(tun_name, "sdnadapter%d", strlen("sdnadapter%d") + 1);
	data->tun_fd = tun_alloc(tun_name, 1);
	printf("tun name %s tunfd %d clientfd %d\n", tun_name, data->tun_fd, data->client_fd);
	iRet = SetupInterFaceParams(tun_name, AF_INET, "192.168.1.1", "255.255.255.0", "AA:BB:CC:DD:EE:FF", 1500, error_buff);

	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
	while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN))
	{
		timeout.tv_sec = data->timeout;
		timeout.tv_usec = 0;
		FD_ZERO(&read_fd_set);
		FD_SET(data->client_fd, &read_fd_set);
		FD_SET(data->tun_fd, &read_fd_set);
		if ((activity = select(1024, &read_fd_set, NULL, NULL, NULL)) < 0)	
		{
			goto Exit_Thread;
		}
		else
		{
			//timeout.tv_sec = data->timeout;
			//timeout.tv_usec = 0;
			if (FD_ISSET(data->tun_fd, &read_fd_set))
			{
				printf("Tun FD waiting for some activity\n");
				/*We are reveiving data on the the tunnel interface from the kernel that means we have to send 
  					Send this data to the other on the DTLS connection hence we write using SSL_write */
				if (SSL_get_shutdown(ssl) == 0) 
				{
					tunnel_recvd_bytes = read(data->tun_fd, tunnel_buffer, 65536);
					if (tunnel_recvd_bytes > 0)
					{
						ssl_written_bytes = SSL_write(ssl, tunnel_buffer, tunnel_recvd_bytes);
						switch (SSL_get_error(ssl, ssl_written_bytes))
						{
							
							case SSL_ERROR_NONE:
									bytes_sent += ssl_written_bytes;
									break;
							case SSL_ERROR_WANT_WRITE:
									break;
							case SSL_ERROR_WANT_READ:
									break;
							case SSL_ERROR_SSL:
									printf("%s (%d)\n", ERR_error_string(ERR_get_error(), tunnel_buffer), SSL_get_error(ssl, tunnel_recvd_bytes));
									goto Exit_Thread;
							case SSL_ERROR_SYSCALL:
									perror("Socket Error :");
									goto Exit_Thread;
							default:
									break;
						}
					}
				}
				else
				{
					goto Exit_Thread;
				}	
			}
			if (FD_ISSET(data->client_fd, &read_fd_set))
			{
				printf("client FD waiting for some activity\n");
				/* We are recieving from the SDN Client on the Socket , the data is to be 
  				recieved , decrypted and again transmitted back to the tun interface, so that it can
 				be read by the kernel as a packet*/
				if (SSL_get_shutdown(ssl) == 0)
                {
					ssl_recvd_bytes = SSL_read(ssl, SSL_Buffer, 65536);
					switch (SSL_get_error(ssl, ssl_recvd_bytes))
					{
						case SSL_ERROR_NONE:
								tunnel_written_bytes = write(data->tun_fd, SSL_Buffer, ssl_recvd_bytes);
								bytes_recvd += tunnel_written_bytes;
								break;
						case SSL_ERROR_WANT_READ:
								break;
						case SSL_ERROR_ZERO_RETURN:
								break;
						case SSL_ERROR_SSL:
								printf("SSL read error: ");
								printf("%s (%d)\n", ERR_error_string(ERR_get_error(), SSL_Buffer), SSL_get_error(ssl, ssl_recvd_bytes));
								break;
						case SSL_ERROR_SYSCALL:
								goto Exit_Thread;
						default:
								goto Exit_Thread;
					}
				}
			
			}
		}	
	}
Exit_Thread:
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(data->client_fd);
	close(data->tun_fd);
	free(data);
	pthread_exit(NULL);
}


int TLS_UDP_CLIENT_CONNECT(struct SDNSSL *this, Address server_address)
{
	int iRet = -1;
	char error_buff[1024];
	SSL *ssl = NULL;
	BIO *bio = NULL;
	struct timeval timeout;
	SSL_THREAD_DATA *data = NULL;
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	pthread_t tid;
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
	if (!this)
		return -1;
	SSL_CTX *ctx = this->ctx;
	if (!ctx)
		return -2;
	ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("\nERROR: Unable to Initialize SSL !");
        SSL_CTX_free(ctx);
		return -3;
	}
	bio = BIO_new_dgram(this->server_fd, BIO_CLOSE);
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &server_address.ss);
	SSL_set_bio(ssl, bio, bio);
	if (SSL_connect(ssl) < 0) {
		perror("SSL_connect");
		printf("%s\n", ERR_error_string(ERR_get_error(), error_buff));
		return -4;
	}
	printf ("Connected\n");
	data = (SSL_THREAD_DATA *)malloc(sizeof(SSL_THREAD_DATA ));
	if (!data)
	{
		printf("Not Enough Memory for Thread\n");
		return -5;
	}
	data->ctx = ctx;
	data->ssl = ssl;
	data->bio = bio;
	data->timeout = 5;
	data->server_fd = this->server_fd;
	memcpy(&(data->server_addr), &server_address, sizeof(server_address));
	iRet = pthread_create(&tid, NULL, HandleUDPClientServer, (void *)data);
	return iRet;
}

void * HandleUDPClientServer(void *arg)
{
	int iRet = 0;
	struct timeval timeout;
	fd_set read_fd_set;
	int  activity = -1;
    int tunnel_recvd_bytes = -1;
    int tunnel_written_bytes = -1;
    int ssl_recvd_bytes = -1;
    int ssl_written_bytes = -1;
    long long bytes_sent = 0;
    long long bytes_recvd = 0;
	char tunnel_buffer[65536];
    char SSL_Buffer[65536];
    char error_buff[1024];
	char tun_name[20];

	if (!arg)
	{
		printf("Invalid Thread Arguments \n Exiting..\n");
		pthread_exit(NULL);
	}
	SSL_THREAD_DATA * data = (SSL_THREAD_DATA *)arg;
	pthread_detach(pthread_self());
	SSL * ssl = data->ssl;
	
	strncpy(tun_name, "sdnadapter%d", strlen("sdnadapter%d") + 1);
	data->tun_fd = tun_alloc(tun_name, 1);
	tun_set_queue(data->tun_fd, 1);
    iRet = SetupInterFaceParams(tun_name, AF_INET, "192.168.0.1", "255.255.255.0", "AA:BB:CC:DD:EE:FF", 1500, error_buff);
	while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN))
    {
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        FD_ZERO(&read_fd_set);
        FD_SET(data->server_fd, &read_fd_set);
        FD_SET(data->tun_fd, &read_fd_set);
        if ((activity = select(1024, &read_fd_set, NULL, NULL, NULL)) < 0)
        {
            goto Exit_Thread_2;
        }
        else
        {
        	timeout.tv_sec = 50;
        	timeout.tv_usec = 0;
            if (FD_ISSET(data->tun_fd, &read_fd_set))
            {
				printf("Tun FD waiting for some activity\n");
                /*We are reveiving data on the the tunnel interface from the kernel that means we have to send 
 *                     Send this data to the other on the DTLS connection hence we write using SSL_write */
                if (SSL_get_shutdown(ssl) == 0)
                {
                    tunnel_recvd_bytes = read(data->tun_fd, tunnel_buffer, 65536);
                    if (tunnel_recvd_bytes > 0)
                    {
                        ssl_written_bytes = SSL_write(ssl, tunnel_buffer, tunnel_recvd_bytes);
                        switch (SSL_get_error(ssl, ssl_written_bytes))
                        {

                            case SSL_ERROR_NONE:
                                    bytes_sent += ssl_written_bytes;
                                    break;
                            case SSL_ERROR_WANT_WRITE:
                                    break;
                            case SSL_ERROR_WANT_READ:
                                    break;
                            case SSL_ERROR_SSL:
                                    printf("%s (%d)\n", ERR_error_string(ERR_get_error(), tunnel_buffer), SSL_get_error(ssl, tunnel_recvd_bytes));
                                    goto Exit_Thread_2;
                            case SSL_ERROR_SYSCALL:
                                    perror("Socket Error :");
                                    goto Exit_Thread_2;
                            default:
                                    break;
                        }
                    }
                }
                else
                {
                    goto Exit_Thread_2;
                }
            }
            if (FD_ISSET(data->server_fd, &read_fd_set))
            {
				printf("Server FD waiting for some activity\n");
                /* We are recieving from the SDN Server on the Socket , the data is to be 
 *                 recieved , decrypted and again transmitted back to the tun interface, so that it can
 *                                 be read by the kernel as a packet*/
                if (SSL_get_shutdown(ssl) == 0)
                {
                    ssl_recvd_bytes = SSL_read(ssl, SSL_Buffer, 65536);
                    switch (SSL_get_error(ssl, ssl_recvd_bytes))
                    {
                        case SSL_ERROR_NONE:
                                tunnel_written_bytes = write(data->tun_fd, SSL_Buffer, ssl_recvd_bytes);
                                bytes_recvd += tunnel_written_bytes;
                                break;
                        case SSL_ERROR_WANT_READ:
                                break;
                        case SSL_ERROR_ZERO_RETURN:
                                break;
                        case SSL_ERROR_SSL:
                                printf("SSL read error: ");
                                printf("%s (%d)\n", ERR_error_string(ERR_get_error(), SSL_Buffer), SSL_get_error(ssl, ssl_recvd_bytes));
                                break;
                        case SSL_ERROR_SYSCALL:
                                goto Exit_Thread_2;
                        default:
                                goto Exit_Thread_2;
                    }
                }
			}
        }
    }
Exit_Thread_2:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(data->server_fd);
    close(data->tun_fd);
    free(data);
    pthread_exit(NULL);
}
