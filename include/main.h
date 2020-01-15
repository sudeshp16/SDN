
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <signal.h>
#include <json-c/json.h>
#include <sdn_tls.h>
#include <sdn_tls_udp.h>
#include <sdn_interface_ops.h>
#include <sdn_tun.h>
#include <sdn_transport.h>
#ifndef __MAIN_H__
#define __MAIN_H__


typedef struct thread_data
{
	int tun_tap_fd;
	int server_fd;
	int client_fd;
	SSL *ssl;	
	char dev[32];
}ThreadData;

typedef struct ConfigData
{
	SERVICEMODE operation_mode;
	TRANSPORT_MODE communication_mode;
	char self_ip[32];
	char dest_ip[32];
	int self_port;
	int dest_port;
    SSL_CTX * ctx;
	SSL *ssl;	
	int address_family;
	short listen_length;
	int is_compression_enabled;
	char * certificate;
	char *key;
}ConfigData;

int main(int argc, char *argv[], char *envp[]);

#endif 	//	__MAIN_H__

