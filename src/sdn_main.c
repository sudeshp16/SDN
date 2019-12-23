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
	SDN_SSL.mode = TRANSPORT_MODE_SCTP;
	SDN_SSL.service_mode = atoi(argv[3]) == 1 ? SERVICEMODE_SERVER : SERVICEMODE_CLIENT;
	const char *pcListenAddr = "0.0.0.0";
	int iPort = 9000;
	if (SDN_SSL.service_mode == SERVICEMODE_SERVER)
	{
		iSocket_fd = StartServer(SDN_SSL.mode, pcListenAddr, 9000, AF_INET, 5, error_buff);
		if (iSocket_fd < 0)
		{
			printf("Error Starting Server %s\n", error_buff);
			exit(1);
		}
	}
	else
	{
		iSocket_fd = StartClient(SDN_SSL.mode, atoi(argv[4]), AF_INET,"127.0.0.1", 9000, error_buff);
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
	printf("Succesfully Destroyed TLS\n");
	return 0;
} 
