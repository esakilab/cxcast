# Makefile

CC = gcc -g -Wall

PROGNAME = cxcast


all: $(PROGNAME)

.c.o:
	$(CC) -c $< -o $@

cxcast: cxcast.c
	$(CC) cxcast.c -o $@

clean:
	rm cxcast
