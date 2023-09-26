ifeq ($(origin CC),default)
CC  = clang
endif
LDFLAGS ?= -ggdb -pthread
CFLAGS += -ggdb -pthread -std=c11 -D_GNU_SOURCE
LIBS ?= -lssl -lcrypto -lpthread -lgcc_s

.PHONY: all clean run

all: sockfun solver/brent solver/signmessage

sockfun.o: sockfun.c sockfun.h
	$(CC) $(CFLAGS) -c -o $@ $<

rsautil.o: rsautil.c rsautil.h
	$(CC) $(CFLAGS) -c -o $@ $<

base64.o: base64.c base64.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockfun: sockfun.o rsautil.o base64.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

solver/brent: solver/brent.c
	$(CC) -O3 -g -o $@ $< -lgmp

solver/signmessage: solver/signmessage.c
	$(CC) -g -o $@ $< -lcrypto

clean:
	rm -f sockfun solver/signmessage solver/brent *.o

run: sockfun
	./sockfun
