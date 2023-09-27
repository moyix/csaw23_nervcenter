ifeq ($(origin CC),default)
CC  = clang
endif
LIBS ?= -lssl -lcrypto -lpthread -lgcc_s
override LDFLAGS += -ggdb -pthread
override CFLAGS += -ggdb -pthread -std=c11 -D_GNU_SOURCE -Wall

.PHONY: all clean run pack_credits

all: sockfun solver/brent solver/signmessage unpack_credits fuzzers

parsers.o: parsers.c parsers.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockfun.o: sockfun.c sockfun.h rsautil.h base64.h credits.h parsers.h
	$(CC) $(CFLAGS) -c -o $@ $<

rsautil.o: rsautil.c rsautil.h base64.h sockfun.h
	$(CC) $(CFLAGS) -c -o $@ $<

base64.o: base64.c base64.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockfun: sockfun.o rsautil.o base64.o parsers.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

fuzzers: fuzzers/client_fuzzer

fuzzers/client_fuzzer: fuzzers/client_fuzzer.c parsers.c parsers.h
	clang -ggdb -O1 -fsanitize=fuzzer,address -o $@ $(word 1,$^) $(word 2,$^)

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
