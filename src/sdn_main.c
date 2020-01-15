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
	fclose(fp);
	jobj = json_tokener_parse(buffer);
	if (!jobj)
	{
		return 0;
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
	SDN_SSL.pLogger = init_logger(NULL, "file", "/tmp/debug_log", 7, 1);
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
/*
	if (SDN_SSL.service_mode == SERVICEMODE_SERVER)
	{
		iSocket_fd = StartServer(SDN_SSL.transportmode, SDN_SSL.szListenAddress, SDN_SSL.iListenPort, SDN_SSL.AddressFamily, 5, error_buff);
		if (iSocket_fd < 0)
		{
			printf("Error Starting Server %s\n", error_buff);
			exit(1);
		}
	}
	else
	{
		iSocket_fd = StartClient(SDN_SSL.transportmode, atoi(argv[4]), AF_INET,"127.0.0.1", 9000, error_buff);
		if (iSocket_fd < 0)
		{
			printf("Error Starting Client \n");
			exit(1);
		}
	}
	SDN_SSL.server_fd = iSocket_fd;
	serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(9000);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	memcpy(&(SDN_SSL.server_address), &serv_addr, sizeof(struct sockaddr_in));
	SDNSSL *Ret = init_tls(&SDN_SSL, argv[1], argv[2], "1.2", "ALL:NULL:eNULL:aNULL");
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
			while (1);
		}
		else
		{
			printf("Failed to Connect to TLS Server\n");
		}
	}
	destroy_tls(&SDN_SSL);
*/
	exit_logger(SDN_SSL.pLogger);
	printf("Succesfully Destroyed TLS\n");
	return 0;
} 
