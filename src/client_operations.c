#include <client_operations.h>
#include <cli_tun.h>

void * Client_Thread(void *data)
{
	pthread_detach(pthread_self());
	
}

