default: sdn-client

sdn-client: src/main.c src/cli_tun.c src/route.c src/tcp.c src/logger.c
	gcc src/main.c src/cli_tun.c src/route.c src/tcp.c src/logger.c -g2 -o sdn-client -I include/ -Wall
clean: 
	rm sdn-client
