CC=gcc
CFLAGS=-Wall -Werror -fpic -O3 -std=gnu11
LD=gcc
LDFLAGS=-shared
LDLIBS=-lm
TARGETS=libfileentropy.so

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

%.so: %.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)
