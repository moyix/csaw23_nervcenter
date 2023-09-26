ifeq ($(origin CC),default)
CC  = clang
endif
LDFLAGS ?= -ggdb -pthread
CFLAGS += -ggdb -pthread -std=c11 -D_GNU_SOURCE
LIBS ?= -lssl -lcrypto -lpthread -lgcc_s

.PHONY: all clean run pack_credits

all: sockfun solver/brent solver/signmessage unpack_credits

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

img/credits/frame_00000001.txt:
	tar xf img/credits.tar.xz

unpack_credits: img/credits/frame_00000001.txt

repack_credits:
	rm -f img/credits.tar.xz
	tar cJf img/credits.tar.xz img/credits/frame_*.txt

clean:
	rm -f sockfun solver/signmessage solver/brent *.o

run: sockfun
	./sockfun
