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
	gedit $(SRCFILES) || pluma $(SRCFILES)

clean :
	rm -vf *.o $(BINARY)

count :
	wc -l $(SRCFILES) | sort -bg

tgz :
	tar -czvf nel.tgz *.c *.h Makefile

