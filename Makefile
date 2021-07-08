CFILES=nel.c helper.c cr.c cr_measure.c cs.c config_chk.c
SRCFILES=$(CFILES) nel.h
BINARY=nel
CC=gcc
CFLAGS=-Wall -Wshadow -Wunused -O
LIBS=-pthread -lpcap

all:
	$(CC) $(CFLAGS) -o $(BINARY) $(CFILES) $(LIBS)

e :
	kate $(SRCFILES) || pluma $(SRCFILES)

clean :
	rm -vf *.o $(BINARY)

count :
	wc -l $(SRCFILES) | sort -bg

tgz :
	tar -czvf nel.tgz $(SRCFILES) Makefile


#### debug/development stuff below

senderlocal :
	./nel sender 127.0.0.1 127.0.0.1

receiverlocal :
	./nel receiver 127.0.0.1 lo


receiverremote :
	./nel receiver 192.168.2.104 wlp2s0

senderremote :
	./nel sender 192.168.2.109 192.168.2.109

