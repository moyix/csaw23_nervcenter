ifeq ($(origin CC),default)
CC  = clang
endif
LDFLAGS ?= -g
CFLAGS += -g -pthread -std=c11
LIBS ?= -lssl -lcrypto -lpthread

all: sockfun solver/brent solver/signmessage

sockfun.o: sockfun.c sockfun.h
	$(CC) $(CFLAGS) -c -o $@ $<

rsautil.o: rsautil.c rsautil.h
	$(CC) $(CFLAGS) -c -o $@ $<

base64.o: base64.c base64.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockfun: sockfun.o rsautil.o base64.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

solver/brent: solver/brent.c
	$(CC) -g -o $@ $< -lgmp

solver/signmessage: solver/signmessage.c
	$(CC) -g -o $@ $< -lcrypto

clean:
	rm -f sockfun solver/signmessage solver/brent *.o
