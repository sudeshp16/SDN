#include <sdn_transport.h>
/*
 * @StartServer
 * 			This Function Starts a TCP/SCTP server in listening mode in IPV4 or IPV6 mode.
 * @params
 * @pcListenAddr 
 * 		type : pointer to character ( string)
 * 		desc: IP/IP6 address to listen on.
 *
 * Author : Sudesh Patil*/
int StartServer(TRANSPORT_MODE mode, const char *pcListenAddr, int iPort, int iAddressFamily, int iBacklog, char *pcError)
{
	int iSocketFD = -1;
	int enable = 1;
	int disable = 0;
	int iRet = -1, sock_reuse_flag =1;
	int i = 0;
	struct sockaddr_in server_addr;
	struct sockaddr_in6 server_addr6;
	struct in6_addr ipv6_result;
	socklen_t iLength;

	if (iAddressFamily == AF_INET)
	{
		if (mode == TRANSPORT_MODE_SCTP)
			iSocketFD = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
		else if (mode == TRANSPORT_MODE_TCP)
			iSocketFD = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		else if (mode == TRANSPORT_MODE_UDP)
			iSocketFD = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		else
			return -1;
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(iPort);
		server_addr.sin_addr.s_addr = inet_addr(pcListenAddr);
		iLength = sizeof(struct sockaddr_in);
	}
	else
	{
		if (mode == TRANSPORT_MODE_SCTP)	// TCP or SCTP
			iSocketFD = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);
		else if (mode == TRANSPORT_MODE_TCP)
			iSocketFD = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		else if (mode == TRANSPORT_MODE_UDP)
			iSocketFD = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		else
			return -1;
		server_addr6.sin6_family = AF_INET;
		server_addr6.sin6_port = htons(iPort);
		if (inet_pton(AF_INET6, pcListenAddr, &ipv6_result) != 1) // success!
		{
			if (pcError)
				snprintf(pcError, strlen(SOCKET_IPV6_ADDR_ERROR) + strlen(strerror(errno)), SOCKET_IPV6_ADDR_ERROR, strerror(errno));
			return -1;
		}
		server_addr6.sin6_addr = ipv6_result;
		server_addr6.sin6_scope_id = 0;
		iLength = sizeof(struct sockaddr_in6);
	}
	if (iSocketFD < 0)
	{
		if (pcError)
			snprintf(pcError, strlen(SOCKET_CREATE_ERROR) + strlen(strerror(errno)), SOCKET_CREATE_ERROR, strerror(errno));
		return -1;
	}
	if ((iRet = setsockopt(iSocketFD, SOL_SOCKET, SO_REUSEADDR, (const void*)&sock_reuse_flag, (socklen_t)sizeof(sock_reuse_flag))) < 0)
	{
		if (pcError)
			snprintf(pcError, strlen(SOCKET_REUSEADDR_ERROR) + strlen(strerror(errno)), SOCKET_REUSEADDR_ERROR, strerror(errno));
	}
	if (mode == TRANSPORT_MODE_SCTP)
	{

		#ifdef SCTP_EVENT
			struct sctp_event event;
			uint16_t event_types[] = {SCTP_ASSOC_CHANGE,
							  SCTP_PEER_ADDR_CHANGE,
							  SCTP_SHUTDOWN_EVENT,
							  SCTP_ADAPTATION_INDICATION};
		#else
			struct sctp_event_subscribe event;
		#endif

		#ifdef SCTP_RCVINFO
			if ((iRet =setsockopt(iSocketFD, IPPROTO_SCTP, SCTP_RECVRCVINFO, &enable, sizeof(enable)) ) < 0);
		#else
			memset(&event, 0, sizeof(event));
			event.sctp_data_io_event = 1;
			if (( iRet = setsockopt(iSocketFD, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(event))) < 0) 
			{
				perror("set event failed");
			}
		#endif
		
		#ifdef SCTP_EVENT
			memset(&event, 0, sizeof(event));
			event.se_assoc_id = SCTP_FUTURE_ASSOC;
			event.se_on = 1;
			for (i = 0; i < sizeof(event_types)/sizeof(uint16_t); i++) 
			{
				event.se_type = event_types[i];
				if ((iRet = setsockopt(iSocketFD, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event))) < 0) 
				{
					perror("setsockopt");
				}
			}
		#else
			memset(&event, 1, sizeof(event));
			if ((iRet = setsockopt(iSocketFD, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(event))) < 0) 
			{
				perror("set event failed");
			}
		#endif

	}
	if ((iRet = bind(iSocketFD, (struct sockaddr *)&server_addr, iLength)) < -1)
	{
		if (pcError)
			snprintf(pcError, strlen(SOCKET_BIND_ERROR) + strlen(strerror(errno)), SOCKET_BIND_ERROR, strerror(errno));
		close(iSocketFD);
		return -2;
	}
	if (mode != TRANSPORT_MODE_UDP)
	{
		printf("I am Listening \n");
		if ((iRet = listen(iSocketFD, iBacklog)) < 0)
		{
			perror("Listen ");
		//	if (pcError)
				//snprintf(pcError, strlen(SOCKET_LISTEN_ERROR) + strlen(strerror(errno)), SOCKET_LISTEN_ERROR, strerror(errno));
			return -3;
		} 
	} 
	return iSocketFD;
}


int StartClient(TRANSPORT_MODE mode, uint16_t iSPort, int iAddressFamily, const char *pcServerAddress, uint16_t iDPort, char *pcError)
{
	int iSocketFD = -1;
	int iRet = -1;
	int i = 0;
	struct sockaddr_in server_addr;
	struct sockaddr_in6 server_addr6;
	struct sockaddr_in client_addr;
	struct sockaddr_in6 client_addr6;
	struct in6_addr ipv6_result;
	socklen_t iLength;

	if (iAddressFamily == AF_INET)
	{
		if (mode == TRANSPORT_MODE_SCTP)
			iSocketFD = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
		else if (mode == TRANSPORT_MODE_TCP)
			iSocketFD = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		else if (mode == TRANSPORT_MODE_UDP)
			iSocketFD = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		else
			return -1;
		if (iSocketFD < 0)
		{
			perror("Socket");
			return -1;
		}
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(iDPort);
		server_addr.sin_addr.s_addr = inet_addr(pcServerAddress);
		iLength = sizeof(struct sockaddr_in);
		if (iSPort != 0)
		{
			client_addr.sin_family = AF_INET;
			client_addr.sin_port = htons(iSPort);
			client_addr.sin_addr.s_addr = INADDR_ANY;
			if ((iRet = bind(iSocketFD, (struct sockaddr *)&client_addr, iLength)) < -1)
			{
				if (pcError)
					snprintf(pcError, strlen(SOCKET_BIND_ERROR) + strlen(strerror(errno)), SOCKET_BIND_ERROR, strerror(errno));
				close(iSocketFD);
				return -1;
			}
		}
    	if (mode == TRANSPORT_MODE_SCTP)
    	{
        	#ifdef SCTP_EVENT
            	struct sctp_event event;
            	uint16_t event_types[] = {SCTP_ASSOC_CHANGE,
                            	  SCTP_PEER_ADDR_CHANGE,
                              	SCTP_SHUTDOWN_EVENT,
                              	SCTP_ADAPTATION_INDICATION};
        	#else
            	struct sctp_event_subscribe event;
        	#endif

        	#ifdef SCTP_RCVINFO
            	if ((iRet =setsockopt(iSocketFD, IPPROTO_SCTP, SCTP_RECVRCVINFO, &enable, sizeof(enable)) ) < 0);
       		#else
            	memset(&event, 0, sizeof(event));
            	event.sctp_data_io_event = 1;
            	if (( iRet = setsockopt(iSocketFD, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(event))) < 0)
            	{
                	perror("set event failed");
            	}
        	#endif

        	#ifdef SCTP_EVENT
            	memset(&event, 0, sizeof(event));
            	event.se_assoc_id = SCTP_FUTURE_ASSOC;
            	event.se_on = 1;
            	for (i = 0; i < sizeof(event_types)/sizeof(uint16_t); i++)
            	{
                	event.se_type = event_types[i];
                	if ((iRet = setsockopt(iSocketFD, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event))) < 0)
                	{
                    	perror("setsockopt");
                	}
            	}
        	#else
            	memset(&event, 1, sizeof(event));
            	if ((iRet = setsockopt(iSocketFD, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(event))) < 0)
            	{
                	perror("set event failed");
            	}
        	#endif

    	}

		/* Commenting This Condition as UDP socket can also Use connect and we require it for SSL/ TLS
		if (mode != TRANSPORT_MODE_UDP)
		{*/
	/*
		if ((iRet =  connect(iSocketFD, (const struct sockaddr *)&server_addr, iLength)) < 0)
		{
			if (pcError)
				perror("Client Connect : ");
			close(iSocketFD);
			return -1;
		}
*/
		//printf("Transport Connected Succesfully fd %d \n", iSocketFD);
		/*}
 		* */
	}
	else	// IPv6
	{
		if (mode == TRANSPORT_MODE_SCTP)
			iSocketFD = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);
		else if (mode == TRANSPORT_MODE_TCP)
			iSocketFD = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		else if (mode == TRANSPORT_MODE_UDP)
			iSocketFD = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		else
			return -1;
		server_addr6.sin6_family = AF_INET;
		server_addr6.sin6_port = htons(iDPort);
		if (inet_pton(AF_INET6, pcServerAddress, &ipv6_result) != 1) // success!
		{
			snprintf(pcError, strlen(SOCKET_IPV6_ADDR_ERROR) + strlen(strerror(errno)), SOCKET_IPV6_ADDR_ERROR, strerror(errno));
			return -2;
		}
		server_addr6.sin6_addr = ipv6_result;
		server_addr6.sin6_scope_id = 0;
		iLength = sizeof(struct sockaddr_in6);
		if (iSPort != 0)
		{
			client_addr6.sin6_family = AF_INET;
			client_addr6.sin6_port = htons(iSPort);
			client_addr6.sin6_addr = ipv6_result;
			client_addr6.sin6_scope_id = 0;
			if ((iRet = bind(iSocketFD, (struct sockaddr *)&client_addr6, iLength)) < -1)
			{
				if (pcError)
					snprintf(pcError, strlen(SOCKET_BIND_ERROR) + strlen(strerror(errno)), SOCKET_BIND_ERROR, strerror(errno));
				close(iSocketFD);
				return -3;
			}
		}
		if (mode == TRANSPORT_MODE_SCTP)
    	{
        	#ifdef SCTP_EVENT
            	struct sctp_event event;
            	uint16_t event_types[] = {SCTP_ASSOC_CHANGE,
                	              SCTP_PEER_ADDR_CHANGE,
                    	          SCTP_SHUTDOWN_EVENT,
                        	      SCTP_ADAPTATION_INDICATION};
        	#else
            	struct sctp_event_subscribe event;
        	#endif

        	#ifdef SCTP_RCVINFO
            	if ((iRet =setsockopt(iSocketFD, IPPROTO_SCTP, SCTP_RECVRCVINFO, &enable, sizeof(enable)) ) < 0);
        	#else
            	memset(&event, 0, sizeof(event));
            	event.sctp_data_io_event = 1;
            	if (( iRet = setsockopt(iSocketFD, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(event))) < 0)
            	{
                	perror("set event failed");
            	}
        #endif

        	#ifdef SCTP_EVENT
            	memset(&event, 0, sizeof(event));
            	event.se_assoc_id = SCTP_FUTURE_ASSOC;
            	event.se_on = 1;
            	for (i = 0; i < sizeof(event_types)/sizeof(uint16_t); i++)
            	{
                	event.se_type = event_types[i];
                	if ((iRet = setsockopt(iSocketFD, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event))) < 0)
                	{
                    	perror("setsockopt");
                	}
            	}
        	#else
            	memset(&event, 1, sizeof(event));
            	if ((iRet = setsockopt(iSocketFD, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(event))) < 0)
            	{
                	perror("set event failed");
            	}
        	#endif

    	}

		/* Commenting This Condition as UDP socket can also Use connect and we require it for SSL/ TLS
		if (mode != TRANSPORT_MODE_UDP)
		{*/
/*
		if ((iRet =  connect(iSocketFD, (const struct sockaddr *)&server_addr6, iLength)) < 0)
		{
			if (pcError)
				snprintf(pcError, strlen(SOCKET_CONNECT_ERROR) + strlen(strerror(errno)), SOCKET_CONNECT_ERROR, strerror(errno));
			close(iSocketFD);
			return -4;
		}
*/
	  /*}
 	* 		*/
	}
	return iSocketFD;
}

int SendData(int iSocketFd, TRANSPORT_MODE mode, char * data, int length, int iAddrFamily, char * pcAddress, uint16_t udp_dport)
{
	int iSentBytes = 0;
	if (mode != TRANSPORT_MODE_UDP) // SCTP or TCP
	{
		if (iSocketFd >= 0 && (data != NULL || length != 0))
			iSentBytes = send(iSocketFd, data, length, 0);
		else
			iSentBytes = 0;
	}
	else	// UDP
	{
		struct sockaddr_in dest_addr;
		struct sockaddr_in6 dest_addr6;
		struct in6_addr ipv6_result;
		socklen_t sock_size;
		if (AF_INET == iAddrFamily)
		{
			dest_addr.sin_family = AF_INET;
			dest_addr.sin_port = htons(udp_dport);
			dest_addr.sin_addr.s_addr = inet_addr(pcAddress);
			sock_size = sizeof(struct sockaddr_in);
			iSentBytes = sendto(iSocketFd, data, length, 0, (struct sockaddr *) &dest_addr, sock_size);
		}
		else if (AF_INET6 == iAddrFamily)
		{
			if (inet_pton(AF_INET6, pcAddress, &ipv6_result) != 1) // success!
        	{
            	return -2;
        	}
			dest_addr6.sin6_family = AF_INET6;
			dest_addr6.sin6_port = htons(udp_dport);
			dest_addr6.sin6_scope_id = 0;
			dest_addr6.sin6_addr = ipv6_result;
			sock_size = sizeof(struct sockaddr_in6);
			iSentBytes = sendto(iSocketFd, data, length, 0, (struct sockaddr *) &dest_addr6, sock_size);
		}
		else
		{
			return -1;
		}
	}
	return 	iSentBytes;
}


int RecvData(int iSocketFd, TRANSPORT_MODE mode, char * buffer, int size, int *iAddrFamily, struct sockaddr * src_addr)
{
    int iRecvdBytes = 0;
    if (mode != TRANSPORT_MODE_UDP) // SCTP or TCP
    {
        if (iSocketFd >= 0 && (buffer != NULL || size != 0))
            iRecvdBytes = recv(iSocketFd, buffer, size, 0);
        else
            iRecvdBytes = 0;
    }
    else    // UDP
    {
        struct sockaddr_in src_addr;
        struct sockaddr_in6 src_addr6;
        struct in6_addr ipv6_result;
        socklen_t sock_size;
        iRecvdBytes = recvfrom(iSocketFd, buffer, size, 0, (struct sockaddr *) &src_addr, &sock_size);
		if (sock_size == sizeof(struct sockaddr_in))
			*iAddrFamily = AF_INET;
		else if (sock_size == sizeof(struct sockaddr_in6))
			*iAddrFamily = AF_INET6;
		else
			return -1;
    }
    return  iRecvdBytes;
}


