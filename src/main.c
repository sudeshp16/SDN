#include <sdn_logger.h>
#include <signal.h>
#include <main.h>
#include <pthread.h>
#include <server_operations.h>

const char *dev = "sdnadapter%d"; 		
ConfigData config;
pthread_mutex_t *mutex_array = NULL;

union sockaddr_ud
{
};

int main(int argc, char *argv[], char *envp[])
{
	int iRet = -1;
	int iSocketFD = -1;
	int iClientSockFd = -1;
	char pcErrorMsg[1024];
	SSL_CTX *ctx = NULL;
	socklen_t socklen;
	struct sockaddr_in client_addr;
	struct sockaddr_in6 in6;
	if (argc < 4)
	{
		printf("Insufficient Arguments need mode(1/0 :1 - client ,0 Server) Ip Address selfPort destport Transport proto addressfamily\n ");
		exit(1);
	}
	config.operation_mode = atoi(argv[1]);
	config.communication_mode = atoi(argv[5]);
	config.address_family = AF_INET;
	pthread_t acceptor_thread_tid;
	if (config.operation_mode == SERVICEMODE_SERVER)
	{	// Server Mode
		strncpy(config.self_ip, argv[2], strlen(argv[2]) > 32 ? 32:strlen(argv[2]));
		config.self_port = atoi(argv[3]);
		config.listen_length = htons(atoi(argv[4]));

		iSocketFD = StartServer(config.communication_mode, config.self_ip, config.self_port, config.address_family, 5, pcErrorMsg);
		printf("TCP Server Listening on %s:%hd\n", config.self_ip, config.self_port);
		ctx = InitSSLServer(&mutex_array, config.certificate, config.key, config.communication_mode, "1.2", "ALL:Cipherlist");
		if (!ctx)
		{
			printf("Failed To iniatialize SSL Server \n");
			exit(-2);
		}
		if (config.communication_mode == TRANSPORT_MODE_TCP)
		{
			while ((iClientSockFd = accept(iSocketFD, (struct sockaddr *)&client_addr, &socklen)) > 0)
			{
				ServerHandleLoop(iClientSockFd , ctx, config.communication_mode);
			}  	
		}
		else if (config.communication_mode == TRANSPORT_MODE_UDP)
		{
			while ((iRet = ServerHandleLoop(iClientSockFd , ctx, config.communication_mode)) > 0)
			{
				
			}	
		}
		else if (config.communication_mode == TRANSPORT_MODE_SCTP)
		{
		
		}
	}
	else
	{	// Client Mode
		strncpy(config.dest_ip, argv[2], strlen(argv[2]) > 32 ? 32:strlen(argv[2]));
		config.self_port = atoi(argv[3]);
		config.dest_port = atoi(argv[4]);
		iSocketFD = StartClient(config.communication_mode, config.self_port, config.address_family, config.dest_ip, config.dest_port, pcErrorMsg);
	}
	if (ctx)
		SSL_CTX_free(ctx);
#ifdef DEBUG
	
#endif 	
	return 0;
}
