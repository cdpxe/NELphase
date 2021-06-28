CFILES=nel.c helper.c cr.c cs.c cr_measure.c
SRCFILES=$(CFILES) nel.h
OBJFILES=nel.o helper.o cr.o cr_measure.o cs.o
BINARY=nel
CC=gcc
CFLAGS=-Wall -Wshadow -Wunused
LIBS=-pthread -lpcap

all:
	$(CC) -O -o $(BINARY) $(CFILES) $(LIBS)

e :
	kate $(SRCFILES) || pluma $(SRCFILES)

clean :
	rm -vf *.o $(BINARY)

count :
	wc -l $(SRCFILES) | sort -bg

tgz :
	tar -czvf nel.tgz *.c *.h Makefile


#### debug/development stuff below

senderlocal :
	./nel sender 127.0.0.1 127.0.0.1

receiverlocal :
	./nel receiver 127.0.0.1 lo


receiverremote :
	./nel receiver 192.168.2.104 wlp2s0

senderremote :
	./nel sender 192.168.2.109 192.168.2.109

