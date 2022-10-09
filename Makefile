CFLAGS = -Wall
CC = gcc

PROGRAMS = main

clean:
	rm -f *.o *~ $(PROGRAMS)
	rm -f ./BLockchain/* $(PROGRAMS)

all: $(PROGRAMS)

primal.o: ./primal/primal.c
	$(CC) -c $(CFLAGS) ./primal/primal.c

rsa.o: ./rsa/rsa.c
	$(CC) -c $(CFLAGS) ./rsa/rsa.c

key.o: ./key/key.c
	$(CC) -c $(CFLAGS) ./key/key.c

signature.o: ./signature/signature.c
	$(CC) -c $(CFLAGS) ./signature/signature.c

protected.o: ./protected/protected.c
	$(CC) -c $(CFLAGS) ./protected/protected.c

cellkey.o: ./cellkey/cellkey.c
	$(CC) -c $(CFLAGS) ./cellkey/cellkey.c

cellprotected.o: ./cellprotected/cellprotected.c
	$(CC) -c $(CFLAGS) ./cellprotected/cellprotected.c

hashtable.o: ./hashtable/hashtable.c
	$(CC) -c $(CFLAGS) ./hashtable/hashtable.c

blockchain.o: ./blockchain_code/blockchain.c
	$(CC) -c $(CFLAGS) ./blockchain_code/blockchain.c

main.o: main.c
	$(CC) -c $(CFLAGS) main.c

main: main.o primal.o rsa.o key.o signature.o protected.o cellkey.o cellprotected.o hashtable.o blockchain.o
	$(CC) -o $@ $(CFLAGS) $^ -g -lm -lssl -lcrypto