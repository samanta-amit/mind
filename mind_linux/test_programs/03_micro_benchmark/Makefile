# Makefile
IDIR = .
CC=gcc
CFLAGS=-I$(IDIR) -lpthread -g -D __TEST__

obj-y += test_protocol.c test_utils.c
obj-cache += test_protocol_coherence.c test_utils.c

default: test_protocol

test_protocol: $(obj-y)
	@make clean
	@mkdir -p bin
	$(CC) -o bin/$@ $^ $(CFLAGS) $(LIBS)

cache_coherence: $(obj-cache)
	@make clean
	@mkdir -p bin
	$(CC) -o bin/$@ $^ $(CFLAGS) $(LIBS)
	@mv bin/cache_coherence bin/test_protocol

clean:
	@rm -f *.o
	@rm -f bin/*

run: test_protocol
	@bin/test_protocol 1 1 1
	@bin/test_protocol 1 2 1
	@bin/test_protocol 1 4 1
	@bin/test_protocol 1 8 1
	@bin/test_protocol 1 16 1

run_remote: test_protocol
	@bin/test_protocol 0 16 1

run_remote_multi: test_protocol
	@bin/test_protocol 0 $(NUM_THREAD) 1 4 $(NODE_ID)

run_remote_mem: test_protocol
	@bin/test_protocol 0 $(NUM_THREAD) 1 1 $(NODE_ID) 2

run_remote_multi_mem: test_protocol
	@bin/test_protocol 0 $(NUM_THREAD) 1 4 $(NODE_ID) 2
	@# bin/test_protocol 0 $(NUM_THREAD) 10 4 $(NODE_ID) 2

run_cache: cache_coherence
	@# bin/test_protocol 1 1 1 1 1024
	@# bin/test_protocol 2 1 1 2 1024
	@# bin/test_protocol 2 1 1 3 1024
	@# bin/test_protocol 2 1 1 4 1024
	@# bin/test_protocol $(NUM_NODE) 1 1 2 1024
	bin/test_protocol $(NUM_NODE) 1 1 4 1024

run_cache_sub: cache_coherence
	@# bin/test_protocol 2 2 0 2 1024
	@# bin/test_protocol 2 2 0 3 1024
	@# bin/test_protocol 2 2 0 4 1024
	@# bin/test_protocol $(NUM_NODE) $(NODE_ID) 0 2 1024
	bin/test_protocol $(NUM_NODE) $(NODE_ID) 0 4 1024

# generate_trace: clean_traces
# 	@cd trace && python3 genTrace.py
# 	@ls -l trace

# clean_traces:
# 	@rm -f trace/multiPage*
# 	@rm -f trace/uniPage*
