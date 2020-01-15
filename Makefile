default: native

native: src/sdn_main.c src/sdn_tls.c src/sdn_tls_sctp.c src/sdn_tls_udp.c src/sdn_tun.c src/logger.c src/sdn_interface_ops.c src/sdn_transport.c
	gcc src/sdn_main.c src/sdn_tls.c src/sdn_tls_sctp.c src/sdn_tls_udp.c src/sdn_tun.c src/logger.c src/sdn_interface_ops.c src/sdn_transport.c -g2 -o sdn-client -I ./include/  -lssl -lcrypto -lpthread -ljson-c
latest: src/sdn_main.c src/sdn_tls.c src/sdn_tls_sctp.c src/sdn_tls_udp.c src/sdn_tun.c src/logger.c src/sdn_interface_ops.c src/sdn_transport.c
	gcc src/sdn_main.c src/sdn_tls.c src/sdn_tls_sctp.c src/sdn_tls_udp.c src/sdn_tun.c src/logger.c src/sdn_interface_ops.c src/sdn_transport.c -g2 -o sdn-client -I ./include/  openssl/openssl-1.0.2u/libssl.a openssl/openssl-1.0.2u/libcrypto.a -ldl -lpthread -ljson-c
clean: 
	rm sdn-client
