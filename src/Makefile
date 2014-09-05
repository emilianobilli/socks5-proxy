
CC := gcc
CFLAGSO := -c -Wall -v -ggdb

all: mem.o sockets.o socks5.o main.o proxy

mem.o: mem.c mem_types.h socks5.h
	$(CC) $(CFLAGSO) mem.c

socks5.o: socks5.h socks5.c mem_types.h mem_proto.h
	$(CC) $(CFLAGSO) socks5.c

sockets.o: sockets.c
	$(CC) $(CFLAGSO) sockets.c

main.o: main.c
	$(CC) $(CFLAGSO) main.c
	

proxy: main.o mem.o sockets.o socks5.o
	$(CC) -Wall -ggdb main.o mem.o sockets.o socks5.o -o proxy

clean:
	rm *.o
	rm proxy