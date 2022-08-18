# Makefile
IDIR = .
CC=gcc
CFLAGS=-I$(IDIR)

obj-y += 001.allocation_test.o

test_001: $(obj-y)
	@mkdir -p bin
	@$(CC) -o bin/$@ $^ $(CFLAGS) $(LIBS)
clean:
	@rm -f *.o
	@rm -f bin/*
