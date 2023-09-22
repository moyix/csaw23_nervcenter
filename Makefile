ifeq ($(origin CC),default)
CC  = clang
endif
CFLAGS ?= -g
LIBS ?= -lssl -lcrypto

all: sockfun

sockfun.o: sockfun.c sockfun.h
	$(CC) $(CFLAGS) -c -o $@ $<

rsautil.o: rsautil.c rsautil.h
	$(CC) $(CFLAGS) -c -o $@ $<

base64.o: base64.c base64.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockfun: sockfun.o rsautil.o base64.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f sockfun *.o
