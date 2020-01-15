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


SDNSSL *init_tls(SDNSSL * thisptr, char * pcCertificate, char *pcPrivate_key, char *pcsSSL_version, char * pcCipherlist)
{
	if (!thisptr)
		return NULL;	
	if (!pcCertificate || !pcPrivate_key || !pcsSSL_version || !pcCipherlist)
		return NULL;
	if (thisptr->transport_mode == TRANSPORT_MODE_UDP)
	{
		thisptr->TLS_TRANSPORT_INIT = InitUDPSSL;
		thisptr->SHUTDOWN_TLS_SERVER = SHUTDOWN_UDP_TLS_SERVER;
		thisptr->serverHandleThread = HandleUDPServerClient;
		thisptr->TLS_SERVER_LISTEN = UDP_TLS_SERVER_LISTEN;
        thisptr->TLS_CLIENT_CONNECT = TLS_UDP_CLIENT_CONNECT;
        thisptr->clientHandleThread = HandleUDPClientServer;
	}
	else if (thisptr->transport_mode == TRANSPORT_MODE_SCTP)
	{
		thisptr->TLS_TRANSPORT_INIT = InitSCTPSSL;
		thisptr->SHUTDOWN_TLS_SERVER = SHUTDOWN_SCTP_TLS_SERVER;
		thisptr->serverHandleThread = HandleSCTPServerClient;
		thisptr->TLS_SERVER_LISTEN = SCTP_TLS_SERVER_LISTEN;
        thisptr->TLS_CLIENT_CONNECT = TLS_SCTP_CLIENT_CONNECT;
        thisptr->clientHandleThread = HandleSCTPClientServer;
	}	
	thisptr->ctx = thisptr->TLS_TRANSPORT_INIT(&mutex_buf, pcCertificate, pcPrivate_key, pcsSSL_version,pcCipherlist, thisptr->service_mode);
	if (!thisptr->ctx)
	{
		//thisptr->pLogger->WriteLog(thisptr->pLogger ,1 , 
		thisptr->pLogger->WriteLog(thisptr->pLogger ,1 , "Failed to Initialized TLS\n");	
		return NULL;
	}
	thisptr->pLogger->WriteLog(thisptr->pLogger ,1 , "SuccessFully Initialized TLS\n");	
	return thisptr;
}


int tls_listen_loop(SDNSSL *thisptr)
{
	int iRet = 0;
	thisptr->listen_exit_flag = 0;
	iRet = thisptr->TLS_SERVER_LISTEN(thisptr, thisptr->ctx, thisptr->server_fd);
	if (iRet)
	{
		thisptr->pLogger->WriteLog(thisptr->pLogger ,1 , "Finished Listening TLS\n");
	}
	return iRet;
}

int tls_client_connect(SDNSSL *thisptr, int address_family, char * pcIP, uint16_t port)
{
	int iRet = 0;
	Address  server_address;
	int iLength = sizeof(thisptr->server_address);
	thisptr->client_bio = BIO_new_dgram(thisptr->server_fd, BIO_NOCLOSE);
	if ((iRet =  connect(thisptr->server_fd, (const struct sockaddr *)&(thisptr->server_address), iLength)) < 0)
    {
         //if (pcError)
         //    snprintf(pcError, strlen(SOCKET_CONNECT_ERROR) + strlen(strerror(errno)), SOCKET_CONNECT_ERROR, strerror(errno));
         close(thisptr->server_fd);
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
			thisptr->pLogger->WriteLog(thisptr->pLogger ,1 , "Failed to Connect IP To IPv6 Server\n");
			return -1;
		}
		serv_addr6.sin6_addr = ipv6_result;
		serv_addr6.sin6_port = htons(port);
		serv_addr6.sin6_scope_id = 0;
		serv_addr6.sin6_family = AF_INET6;
		memcpy(&server_address, &serv_addr6, sizeof(struct sockaddr_in6));
	}
	iRet = thisptr->TLS_CLIENT_CONNECT(thisptr,server_address);
	return iRet;
}

void destroy_tls(SDNSSL *thisptr)
{
	thisptr->SHUTDOWN_TLS_SERVER(thisptr->ctx, &mutex_buf);
}
