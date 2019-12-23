#include <sys/socket.h>
#include <sys/types.h>

#ifndef __COMMUNICATE_H__
#define __COMMUNICATE_H__


/*
 * @function StartSCTPServer
 *
 *@Params addr char pointer "Ip address of Listening Server to be assigned" 
 *
 * @returns File Descriptor of Listening Server , -1 on Failure
 * 	and reason in msg
 *
 * 	@Author Sudesh Patil
 * 	*/
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/sctp.h>

#ifndef SCTP_FUTURE_ASSOC
	#ifdef SCTP_EVENT
		#define SCTP_FUTURE_ASSOC 0
	#endif
#endif

#define SOCKET_CREATE_ERROR "Error in Creating socket errno %d error %s\n"
#define SOCKET_BIND_ERROR "Error in Binding socket errno %d error %s\n"
#define SOCKET_LISTEN_ERROR "Error in Listening socket errno %d error %s\n"
#define SOCKET_ACCEPT_ERROR "Error in Accepting socket errno %d error %s\n"
#define SOCKET_CONNECT_ERROR "Error in Connecting socket errno %d error %s\n"
#define SOCKET_INVALID_SD_ERROR "Error Invalid Socket Descriptor File %d error %s\n"
#define SOCKET_IPV6_ADDR_ERROR "Error in Converting IPv6 Address errno %d error %s\n"
#define SOCKET_REUSEADDR_ERROR "Error Setting Socket Reuse option on Socket errno %d error %s\n"

typedef enum  SERVICEMODE
{
    SERVICEMODE_SERVER,
    SERVICEMODE_CLIENT
} SERVICEMODE;


typedef enum TRANSPORT_MODE
{
	TRANSPORT_MODE_TCP,
	TRANSPORT_MODE_SCTP,
	TRANSPORT_MODE_UDP
}TRANSPORT_MODE;


int StartServer(TRANSPORT_MODE mode, const char *pcListenAddr, int iPort, int iAddressFamily, int iFlags, char *pcError);
int StartClient(TRANSPORT_MODE mode, uint16_t iSPort, int iAddressFamily, const char *pcServerAddress, uint16_t iDPort, char *pcError);
#endif	//__COMMUNICATE_H__
