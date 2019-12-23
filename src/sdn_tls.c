/*File : sdn_tls_udp.c 
 * 	Copyright Infinite Dreams Solutions 
 * 	This File contains functions necessary for Establishing DTLS 
 * 		using UDP.
 *
 * 		Author: Sudesh Patil 
 * 		Date : 2019-07-12
 *
 * */
#include <sdn_tls.h>
#include <sdn_tls_udp.h>
#include <sdn_tls_sctp.h>

pthread_mutex_t* mutex_buf = NULL;


SDNSSL *init_tls(SDNSSL * this, char * pcCertificate, char *pcPrivate_key, char *pcsSSL_version, char * pcCipherlist)
{
	if (!this)
		return NULL;	
	if (!pcCertificate || !pcPrivate_key || !pcsSSL_version || !pcCipherlist)
		return NULL;
	if (this->mode == TRANSPORT_MODE_UDP)
	{
		this->TLS_TRANSPORT_INIT = InitUDPSSL;
		this->SHUTDOWN_TLS_SERVER = SHUTDOWN_UDP_TLS_SERVER;
		this->serverHandleThread = HandleUDPServerClient;
		this->TLS_SERVER_LISTEN = UDP_TLS_SERVER_LISTEN;
        this->TLS_CLIENT_CONNECT = TLS_UDP_CLIENT_CONNECT;
        this->clientHandleThread = HandleUDPClientServer;
	}
	else if (this->mode == TRANSPORT_MODE_SCTP)
	{
		this->TLS_TRANSPORT_INIT = InitSCTPSSL;
		this->SHUTDOWN_TLS_SERVER = SHUTDOWN_SCTP_TLS_SERVER;
		this->serverHandleThread = HandleSCTPServerClient;
		this->TLS_SERVER_LISTEN = SCTP_TLS_SERVER_LISTEN;
        this->TLS_CLIENT_CONNECT = TLS_SCTP_CLIENT_CONNECT;
        this->clientHandleThread = HandleSCTPClientServer;
	}	
	this->ctx = this->TLS_TRANSPORT_INIT(&mutex_buf, pcCertificate, pcPrivate_key, pcsSSL_version,pcCipherlist, this->service_mode);
	if (!this->ctx)
	{
		printf("Failed to Initialized TLS\n");	
		return NULL;
	}
	printf("SuccessFully Initialized TLS\n");	
	return this;
}


int tls_listen_loop(SDNSSL *this)
{
	int iRet = 0;
	this->listen_exit_flag = 0;
	iRet = this->TLS_SERVER_LISTEN(this, this->ctx, this->server_fd);
	if (iRet)
	{
		printf("Finished Listening TLS\n");
	}
	return iRet;
}

int tls_client_connect(SDNSSL *this, int address_family, char * pcIP, uint16_t port)
{
	int iRet = 0;
	Address  server_address;
	int iLength = sizeof(this->server_address);
	this->client_bio = BIO_new_dgram(this->server_fd, BIO_NOCLOSE);
	if ((iRet =  connect(this->server_fd, (const struct sockaddr *)&(this->server_address), iLength)) < 0)
    {
         //if (pcError)
         //    snprintf(pcError, strlen(SOCKET_CONNECT_ERROR) + strlen(strerror(errno)), SOCKET_CONNECT_ERROR, strerror(errno));
         close(this->server_fd);
         return -4;
   	}
	if (AF_INET == address_family)
	{
		struct sockaddr_in serv_addr;
		serv_addr.sin_addr.s_addr = inet_addr(pcIP);
		serv_addr.sin_port = htons(port);
		serv_addr.sin_family = AF_INET;
		memcpy(&server_address, &serv_addr, sizeof(struct sockaddr_in));
	}
	else
	{
		struct sockaddr_in6 serv_addr6;
		struct in6_addr ipv6_result;
		if ((iRet = inet_pton(AF_INET6, pcIP, &ipv6_result) != 1)) 
		{
			printf("Failed to Connect IP To IPv6 Server\n");
			return -1;
		}
		serv_addr6.sin6_addr = ipv6_result;
		serv_addr6.sin6_port = htons(port);
		serv_addr6.sin6_scope_id = 0;
		serv_addr6.sin6_family = AF_INET6;
		memcpy(&server_address, &serv_addr6, sizeof(struct sockaddr_in6));
	}
	iRet = this->TLS_CLIENT_CONNECT(this,server_address);
	return iRet;
}

void destroy_tls(SDNSSL *this)
{
	this->SHUTDOWN_TLS_SERVER(this->ctx, &mutex_buf);
}
