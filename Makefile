default: sdn-client

sdn-client: src/sdn_main.c src/sdn_tls.c src/sdn_tls_sctp.c src/sdn_tls_udp.c src/sdn_tun.c src/logger.c src/sdn_interface_ops.c src/sdn_transport.c
	gcc src/sdn_main.c src/sdn_tls.c src/sdn_tls_sctp.c src/sdn_tls_udp.c src/sdn_tun.c src/logger.c src/sdn_interface_ops.c src/sdn_transport.c -g2 -o sdn-client -I ./include/ -Wall -lssl -lcrypto -lpthread
clean: 
	rm sdn-client
