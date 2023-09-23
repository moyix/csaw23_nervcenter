ifeq ($(origin CC),default)
CC  = clang
endif
LDFLAGS ?= -g
CFLAGS += -g -pthread -std=c11
LIBS ?= -lssl -lcrypto -lpthread

all: sockfun brent

sockfun.o: sockfun.c sockfun.h
	$(CC) $(CFLAGS) -c -o $@ $<

rsautil.o: rsautil.c rsautil.h
	$(CC) $(CFLAGS) -c -o $@ $<

base64.o: base64.c base64.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockfun: sockfun.o rsautil.o base64.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

brent: brent.c
	$(CC) -g -o $@ $< -lgmp

clean:
	rm -f sockfun brent *.o
