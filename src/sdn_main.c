#include <main.h>

const char *dev = "sdnadapter%d";
ConfigData config;

void iSignalHandler(int iSignal, siginfo_t * info, void * data)
{
	if (iSignal == SIGPIPE)
	{
		printf("Sigpipe Recvied\n");
	}
}

int RegisterSignals()
{
}

int ParseConfig(const char * pcConfigFile, SDNSSL * pSdnConfig)
{
	int iRet = 0;
	FILE *fp = NULL;
	char buffer[65535];
	struct json_object *jobj = NULL;
	enum json_type type;
	fp = fopen(pcConfigFile, "r");
	if (fp == NULL)
	{
		printf("Failed to open file \n");	
		return 0;
	}
	iRet = fread(buffer, 1, 65535, fp);
	if (iRet <= 0)
	{
		fclose(fp);
		return 0;
	}
	printf("Read from json file : %s\n", buffer);
	fclose(fp);
	jobj = json_tokener_parse(buffer);
	if (!jobj)
	{
		printf("Empty jobj\n");
		return 0;
	}
	json_object_object_foreach(jobj, key, val)
	{
		if (strncmp(key, "Operation mode", strlen(key) > strlen("Operation mode") ? strlen(key): strlen("Operation mode")) == 0)
		{
			const char *temp = json_object_get_string(val);
			if (strncmp(temp, "Client", strlen(temp) > strlen("Client") ? strlen(temp): strlen("Client")) == 0)
			{
				pSdnConfig->service_mode = SERVICEMODE_CLIENT;
			}
			else
			{
				pSdnConfig->service_mode = SERVICEMODE_SERVER;
			}
		}
		else if (strncmp(key, "Transport Protocol", strlen(key) > strlen("Transport Protocol") ? strlen(key): strlen("Transport Protocol")) == 0)
		{
			const char *temp = json_object_get_string(val);
			if (strncmp(temp, "UDP", strlen(temp) > strlen("UDP") ? strlen(temp): strlen("UDP")) == 0)
			{
				pSdnConfig->transport_mode = TRANSPORT_MODE_UDP;
			}
			else if (strncmp(temp, "SCTP", strlen(temp) > strlen("SCTP") ? strlen(temp): strlen("SCTP")) == 0)
			{
				pSdnConfig->transport_mode = TRANSPORT_MODE_SCTP;
			}else
			{
				pSdnConfig->transport_mode = TRANSPORT_MODE_TCP;
			}
		}
		else if (strncmp(key, "IP Address", strlen(key) >= strlen("IP Address") ? strlen(key): strlen("IP Address")) == 0)
		{
			const char *temp = json_object_get_string(val);
			strncpy(pSdnConfig->szListenAddress, temp, strlen(temp) +1);
		}
		else if (strncmp(key, "Connect IP Address", strlen(key) >= strlen("Connect IP Address") ? strlen(key): strlen("Connect IP Address")) == 0)
		{
			const char *temp = json_object_get_string(val);
			strncpy(pSdnConfig->szConnectAddress, temp, strlen(temp) +1);
		}
		else if (strncmp(key, "Port", strlen(key) >= strlen("Port") ? strlen(key): strlen("Port")) == 0)
		{
			pSdnConfig->iListenPort = json_object_get_int(val);
		}
		else if (strncmp(key, "Connect Port", strlen(key) >= strlen("Connect Port") ? strlen(key): strlen("Connect Port")) == 0)
		{
			pSdnConfig->iConnectPort = json_object_get_int(val);
		
		}else if (strncmp(key, "Tun Adapter IP", strlen(key) >= strlen("Tun Adapter IP") ? strlen(key): strlen("Tun Adapter IP")) == 0)
		{
			const char *temp = json_object_get_string(val);
			//strncpy(pSdnConfig->szListenAddress, , strlen(temp) +1);
	
		}else if (strncmp(key, "IP Protocol", strlen(key) >= strlen("IP Protocol") ? strlen(key): strlen("IP Protocol")) == 0)
		{
			const char *temp = json_object_get_string(val);
			if (strncmp(temp, "ipv4", strlen(temp) > strlen("ipv4") ? strlen(temp): strlen("ipv4")) == 0)
			{
				pSdnConfig->iAddress_Family = AF_INET;
			}
			else
			{
				pSdnConfig->iAddress_Family = AF_INET6;
			}
		}
	}
	printf("jobj from str:\n---\n%s\n---\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
	return 1;
}
/*mode server/client
 * IP_PROTO: v4/v6
 * Transport Protocol : TCP/UDP/SCTP
 *IP address : Array[]
 Port No: int
	{
		"IP Protocol" : "ipv4",
		"Transport Protocol": "SCTP",
		"IP Address" : "0.0.0.0",
		"Port "	: 9000
	}
  */

int main(int argc, char *argv[], char *envp[])
{
	int iRet = -1;
	int iSocket_fd;
	char error_buff[1024];
	struct sigaction act;
	SDNSSL SDN_SSL;
	struct sockaddr_in serv_addr;	
	act.sa_sigaction = iSignalHandler;
	act.sa_flags = SA_SIGINFO;
	sigaction(SIGPIPE, &act, NULL);
	memset(&SDN_SSL, 0, sizeof(SDN_SSL));
	SDN_SSL.pLogger = init_logger(NULL, "syslog", "debug_log", 7, 1);
	if (SDN_SSL.pLogger == NULL)
	{
		printf("Failed to intialize Logs , Logs will be Disabled \n");
	}
/*
	SDN_SSL.mode = TRANSPORT_MODE_SCTP;
	SDN_SSL.service_mode = atoi(argv[3]) == 1 ? SERVICEMODE_SERVER : SERVICEMODE_CLIENT;
	const char *pcListenAddr = "0.0.0.0";
	int iPort = 9000;
*/
	ParseConfig(argv[1], &SDN_SSL);
	if (SDN_SSL.service_mode == SERVICEMODE_SERVER)
	{
		iSocket_fd = StartServer(SDN_SSL.transport_mode, SDN_SSL.szListenAddress, SDN_SSL.iListenPort, SDN_SSL.iAddress_Family, 5, error_buff);
		if (iSocket_fd < 0)
		{
			printf("Error Starting Server %s\n", error_buff);
			exit(1);
		}
		serv_addr.sin_family = SDN_SSL.iAddress_Family;
    	serv_addr.sin_port = htons(SDN_SSL.iListenPort);
    	serv_addr.sin_addr.s_addr = inet_addr(SDN_SSL.szListenAddress);
	}
	else
	{
		iSocket_fd = StartClient(SDN_SSL.transport_mode, SDN_SSL.iListenPort, SDN_SSL.iAddress_Family , SDN_SSL.szConnectAddress, SDN_SSL.iConnectPort, error_buff);
		if (iSocket_fd < 0)
		{
			printf("Error Starting Client \n");
			exit(1);
		}
		serv_addr.sin_family = SDN_SSL.iAddress_Family;
    	serv_addr.sin_port = htons(SDN_SSL.iConnectPort);
    	serv_addr.sin_addr.s_addr = inet_addr(SDN_SSL.szConnectAddress);
	}
	SDN_SSL.server_fd = iSocket_fd;
	if (SDN_SSL.iAddress_Family == AF_INET)
	{
		memcpy(&(SDN_SSL.server_address), &serv_addr, sizeof(struct sockaddr_in));
	}
	else
	{
		memcpy(&(SDN_SSL.server_address), &serv_addr, sizeof(struct sockaddr_in6));
	}
	SDNSSL *Ret = init_tls(&SDN_SSL, argv[2], argv[3], "1.2", "ALL:NULL:eNULL:aNULL");
	if (Ret == NULL)
	{
		close(iSocket_fd);
		printf("Failed to init TLS \n");
		exit(-1);
	}
	if (SDN_SSL.service_mode == SERVICEMODE_SERVER)
	{
		iRet = tls_listen_loop(&SDN_SSL);
		{
		
		}
	}
	else
	{
		iRet = tls_client_connect(&SDN_SSL, AF_INET, "127.0.0.1", 9000); 
		if (iRet >= 0)
		{
		}
		else
		{
			printf("Failed to Connect to TLS Server\n");
		}
	}
	destroy_tls(&SDN_SSL);
	iRet = (SDN_SSL.pLogger)->WriteLog(SDN_SSL.pLogger, 1, "Succesfully Destroyed TLS\n");
	printf("Writen bytes  %d", iRet);
	exit_logger(SDN_SSL.pLogger);
	return 0;
} 
