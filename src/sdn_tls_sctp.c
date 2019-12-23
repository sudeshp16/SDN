#include <sdn_tls.h>
#include <sdn_tls_sctp.h>
#include <sdn_interface_ops.h>
#include <sdn_tun.h>

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

int Crypto_Thread_init_sctp(pthread_mutex_t **mutex_buf)
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

int  Crypto_Thread_destroy_sctp(pthread_mutex_t **mutex)
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


void handle_notifications(BIO *bio, void *context, void *buf) {
	struct sctp_assoc_change *sac;
	struct sctp_send_failed *ssf;
	struct sctp_paddr_change *spc;
	struct sctp_remote_error *sre;
	union sctp_notification *snp = buf;
	char addrbuf[INET6_ADDRSTRLEN];
	const char *ap;
	Address addr;

	switch (snp->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		sac = &snp->sn_assoc_change;
		printf("NOTIFICATION: assoc_change: state=%hu, error=%hu, instr=%hu outstr=%hu\n",
		sac->sac_state, sac->sac_error, sac->sac_inbound_streams, sac->sac_outbound_streams);
		break;

	case SCTP_PEER_ADDR_CHANGE:
		spc = &snp->sn_paddr_change;
		addr.ss = spc->spc_aaddr;
		if (addr.ss.ss_family == AF_INET) {
			ap = inet_ntop(AF_INET, &addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN);
		} else {
			ap = inet_ntop(AF_INET6, &addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN);
		}
		printf("NOTIFICATION: intf_change: %s state=%d, error=%d\n", ap, spc->spc_state, spc->spc_error);
		break;

	case SCTP_REMOTE_ERROR:
		sre = &snp->sn_remote_error;
		printf("NOTIFICATION: remote_error: err=%hu len=%hu\n", ntohs(sre->sre_error), ntohs(sre->sre_length));
		break;

	case SCTP_SEND_FAILED:
		ssf = &snp->sn_send_failed;
		printf("NOTIFICATION: sendfailed: len=%u err=%d\n", ssf->ssf_length, ssf->ssf_error);
		break;

	case SCTP_SHUTDOWN_EVENT:
		printf("NOTIFICATION: shutdown event\n");
		break;

	case SCTP_ADAPTATION_INDICATION:
		printf("NOTIFICATION: adaptation event\n");
		break;

	case SCTP_PARTIAL_DELIVERY_EVENT:
		printf("NOTIFICATION: partial delivery\n");
		break;

#ifdef SCTP_AUTHENTICATION_EVENT
	case SCTP_AUTHENTICATION_EVENT:
		printf("NOTIFICATION: authentication event\n");
		break;
#endif

#ifdef SCTP_SENDER_DRY_EVENT
	case SCTP_SENDER_DRY_EVENT:
		printf("NOTIFICATION: sender dry event\n");
		break;
#endif

	default:
		printf("NOTIFICATION: unknown type: %hu\n", snp->sn_header.sn_type);
		break;
	}
}



int dtls_verify_callback_sctp(int ok, X509_STORE_CTX *ctx)
{
	// Always Returns 1 for Client Certificate Verification
	return 1;
}

SSL_CTX * InitSCTPSSL(pthread_mutex_t **mutex, char * pcCertificate, char *pcPrivate_key, char *pcsSSL_version, char * pcCipherlist, SERVICEMODE mode)
{

	int iRet = 0;
    SSL_CTX *ctx = NULL;
	SSL_load_error_strings();
    SSL_library_init(); /* initialize library */
    OpenSSL_add_ssl_algorithms();
    if (mutex)
    {
        iRet = Crypto_Thread_init_sctp(mutex);
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
        printf("ERROR: Invalid Cipher List\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
	pid_t pid = getpid();
    if( !SSL_CTX_set_session_id_context(ctx, (void*)&pid, sizeof pid) )
        perror("SSL_CTX_set_session_id_context");

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    if (!SSL_CTX_use_certificate_file(ctx, pcCertificate, SSL_FILETYPE_PEM)){
        printf("ERROR: Certificate not found!");
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
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback_sctp);
    SSL_CTX_set_read_ahead(ctx, 1);
	printf("Success fully started TLSi %p \n", ctx);
	return ctx;
}


void SHUTDOWN_SCTP_TLS_SERVER(SSL_CTX *ctx, pthread_mutex_t **mutex)
{
	if (mutex)
	{
		Crypto_Thread_destroy_sctp(mutex);
	}
	SSL_CTX_free(ctx);
}

int SCTP_TLS_SERVER_LISTEN(SDNSSL *this, SSL_CTX *ctx, int iSocketFD)
{
	char SSL_Buffer[65536];
	struct timeval timeout;
	socklen_t len;
	Address server_addr, client_addr;
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	int client_fd = -1;
	BIO * cli_bio = NULL;
	BIO *bio = NULL;
	if (!ctx || !iSocketFD)
	{
		printf("Ctx %p or Socket desc %d Failed \n", ctx, iSocketFD);
		return -1;
	}
	len = sizeof(server_addr);
	getsockname(iSocketFD, (struct sockaddr*)&server_addr, &len);
	bio = BIO_new_dgram(iSocketFD, BIO_NOCLOSE);
	if (bio == NULL)
	{
		printf("ERROR: Failed To Create SSL Bio client fd %d %s\n", iSocketFD, ERR_error_string(ERR_get_error(), SSL_Buffer));
		ERR_print_errors_fp(stderr);
	}
	printf("Successfully Created BIO %p\n", bio);
	while (!this->listen_exit_flag)
	{
		pthread_t tid;
		SSL_THREAD_DATA *thread_data = NULL;
		memset(&client_addr, 0, sizeof(client_addr));
		thread_data = (SSL_THREAD_DATA *)malloc(sizeof(SSL_THREAD_DATA));	
		if (!thread_data)
		{
			printf("Not Enough Memory !!!\n");
			return -2;
		}
		client_fd = accept(iSocketFD, (struct sockaddr *)&client_addr, &len);
		thread_data->client_fd = client_fd;
		thread_data->ctx = ctx;
		thread_data->ssl = SSL_new(ctx);
		bio = BIO_new_dgram(client_fd, BIO_NOCLOSE);
		thread_data->bio = bio;
		printf("Client Fd %d threaddata->bio %p\n", thread_data->client_fd, thread_data->bio);
		thread_data->server_fd = iSocketFD;
    	if (thread_data->bio == NULL)
    	{
       		SSL_free(thread_data->ssl);
       		printf("ERROR: Failed To Create SSL Bio client fd %d %s\n", iSocketFD, ERR_error_string(ERR_get_error(), SSL_Buffer));
       		//return -3;
    	}
    	else
		{
			BIO_ctrl(thread_data->bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
			//SSL_set_bio(thread_data->ssl, thread_data->bio, thread_data->bio);
			printf("Awaiting for new TLS connection\n");
		/*
			thread_data->server_addr.s4.sin_family = AF_INET;
			thread_data->server_addr.s4.sin_addr.s_addr = INADDR_ANY;
			thread_data->server_addr.s4.sin_port = htons(9000);
		*/
			memcpy(&thread_data->server_addr, &server_addr, sizeof(struct sockaddr_storage));
			memcpy(&thread_data->client_addr, &client_addr, sizeof(struct sockaddr_storage));
			printf("Got a new DTLS SCTP connection, will create a new thread\n");
			pthread_create(&tid, NULL, HandleSCTPServerClient, (void *)thread_data);	
		
		}
		/*Loop Forever*/
	}
	return 0;
}


void * HandleSCTPServerClient(void * args)
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
	char interface_name[20];
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
	SSL_set_bio(ssl, data->bio, data->bio);
	/* Finish handshake */
	do { iRet = SSL_accept(ssl); }
	while (iRet == 0);
	if (iRet < 0) {
		perror("SSL_accept");
		printf("%s\n", ERR_error_string(ERR_get_error(), error_buff));
	}
	printf("Accepted SSL Handshake from New Connection\n");
	strncpy(interface_name, "sdnseradpt%d", strlen("sdnseradpt%d") + 1);
	data->tun_fd = tun_alloc(interface_name, 1);
	iRet = SetupInterFaceParams(interface_name, AF_INET, "192.168.1.1", "255.255.255.0", "AA:BB:CC:DD:EE:FF", 1500, error_buff);

	while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN))
	{
		timeout.tv_sec = data->timeout;
		timeout.tv_usec = 0;
		FD_ZERO(&read_fd_set);
		FD_SET(data->client_fd, &read_fd_set);
		FD_SET(data->tun_fd, &read_fd_set);
		sleep(5);
		if ((activity = select(FD_SETSIZE, &read_fd_set, NULL, NULL, &timeout)) < 0)	
		{
			goto Exit_Thread;
		}
		else
		{
			if (FD_ISSET(data->tun_fd, &read_fd_set))
			{
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


int TLS_SCTP_CLIENT_CONNECT(struct SDNSSL *this, Address server_address)
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
	#ifdef OPENSSL_NO_SCTP
		printf("NoSCTP is defined \n");
	#endif
	printf("Server fd %d\n", this->server_fd);
	bio = this->client_bio;
	//bio = BIO_new_dgram_sctp(this->server_fd, BIO_NOCLOSE);
	if (bio == NULL)
	{
		printf("\nERROR: Unable to Create new sctp client bio\n %s!\n", ERR_error_string(ERR_get_error(), error_buff));
		return -4;
	}
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &server_address.ss);
	
	BIO_dgram_sctp_notification_cb(bio, handle_notifications, (void*) ssl);
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
	iRet = pthread_create(&tid, NULL, HandleSCTPClientServer, (void *)data);
	return iRet;
}

void * HandleSCTPClientServer(void *arg)
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
	char interface_name[20];
	if (!arg)
	{
		printf("Invalid Thread Arguments \n Exiting..\n");
		pthread_exit(NULL);
	}
	SSL_THREAD_DATA * data = (SSL_THREAD_DATA *)arg;
	pthread_detach(pthread_self());
	SSL * ssl = data->ssl;
	//SSL_set_bio(ssl, data->bio, data->bio);
	strncpy(interface_name, "sdncliadapter%d", strlen("sdncliadapter%d")+1);
	data->tun_fd = tun_alloc(interface_name, 1);
	tun_set_queue(data->tun_fd, 1);
    iRet = SetupInterFaceParams(interface_name, AF_INET, "192.168.0.1", "255.255.255.0", "AA:BB:CC:DD:EE:FF", 1500, error_buff);
	while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN))
    {
        timeout.tv_sec = data->timeout;
        timeout.tv_usec = 0;
        FD_ZERO(&read_fd_set);
        FD_SET(data->server_fd, &read_fd_set);
        FD_SET(data->tun_fd, &read_fd_set);
		sleep(5);
        if ((activity = select(FD_SETSIZE, &read_fd_set, NULL, NULL, &timeout)) < 0)
        {
            goto Exit_Thread_2;
        }
        else
        {
            if (FD_ISSET(data->tun_fd, &read_fd_set))
            {
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
	printf("Exitng thread\n");
    pthread_exit(NULL);
}
