#ifndef __SNIFF_H__
#define __SNIFF_H__

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <pub_private_enc_dec.h>

#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN	6
#endif


int SniffData(pcap_handler fpCallbackHandler, const char *pcInterface, const char * pcFilter, const unsigned char *key);

#endif	// __SNIFF_H__
