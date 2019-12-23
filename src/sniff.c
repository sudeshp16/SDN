#include <sniff.h>
#include <sys/socket.h>
#include <netinet/ip.h> /* superset of previous */
#include <netinet/in.h>
#include <netinet/if_ether.h>


void DecryptData_TCP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
	u_char protocol = 0;
	const u_char *ip_header = NULL;
    const u_char *tcp_header = NULL;
    const u_char *udp_header = NULL;
    const u_char *sctp_header = NULL;
    const u_char *payload = NULL;
	struct ether_header *eth_header = NULL;
	int total_headers_size = 0, payload_length = 0;
	int ip_header_length = 0, tcp_header_length = 0;

    eth_header = (struct ether_header *) packet;
	if (!eth_header)
		return;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an Ethernet packet. Skipping...\n\n");
        return;
    }
	printf("Total packet available: %d bytes\n", pkthdr->caplen);
    printf("Expected packet size: %d bytes\n", pkthdr->len);
	ip_header = packet +  ETHER_HDRLEN;
	ip_header_length = ((*ip_header) & 0x0F);
	ip_header_length = ip_header_length * 4;
	printf("IP header length (IHL) in bytes: %d\n", ip_header_length);
	protocol = *(ip_header + 9);
    if (protocol == IPPROTO_TCP) 
	{
		tcp_header = packet + ETHER_HDRLEN + ip_header_length;
		tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
		tcp_header_length = tcp_header_length * 4;
    	printf("TCP header length in bytes: %d\n", tcp_header_length);
		total_headers_size = ETHER_HDRLEN + ip_header_length + tcp_header_length;
		payload_length = pkthdr->caplen - (ETHER_HDRLEN + ip_header_length + tcp_header_length);
		payload = packet + total_headers_size;
		printf("payload %s", payload); 
    }
	else if (protocol == IPPROTO_UDP) 
	{
		udp_header = packet + ETHER_HDRLEN + ip_header_length;
		payload = packet + ETHER_HDRLEN + ip_header_length + 8;
		payload_length = *((uint16_t *)(packet + ETHER_HDRLEN + ip_header_length + 4));
	}
	else if (protocol == IPPROTO_SCTP)
	{
		sctp_header = packet + ETHER_HDRLEN + ip_header_length;
		payload = sctp_header + 28;
	}
}


int SniffData(pcap_handler fpCallbackHandler, const char *pcInterface, const char * pcFilter, const unsigned char * key)
{
    pcap_t *handle = NULL;
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */	
	char errbuf[PCAP_ERRBUF_SIZE];
	int num_packets = -1; 			/* Infinite Packets */
	RSA * priv_key_rsa = NULL;
	int public = 1;
	if (!fpCallbackHandler)
		return -1;
	if (pcap_lookupnet(pcInterface, &netp, &maskp, errbuf) == -1) 
	{
		 fprintf(stderr, "Can't get netmask for device %s\n", pcInterface);
		 netp = 0;
		 maskp = 0;
	}
	priv_key_rsa = GenerateRSA(key, public);
	if (!priv_key_rsa)
		return -2;
	handle = pcap_open_live(pcInterface, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) 
	{
		 fprintf(stderr, "Couldn't open device %s: %s\n", pcInterface, errbuf);
		 return -3;
	}	
	if (pcap_compile(handle, &fp, pcFilter, 0, netp) == -1) 
	{
		if (pcap_setfilter(handle, &fp) == -1) 
		{
			fprintf(stderr, "Couldn't install filter %s: %s\n", pcFilter, pcap_geterr(handle));
			return -4;
		}
	}
	pcap_loop(handle, num_packets, fpCallbackHandler, NULL);
	pcap_freecode(&fp);
	pcap_close(handle);
	return 0;
}

//int bytes_written = pcap_inject(handle, &raw_bytes, sizeof(raw_bytes));
