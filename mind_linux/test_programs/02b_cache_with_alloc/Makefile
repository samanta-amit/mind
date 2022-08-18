# Makefile
IDIR = .
SHELL := /bin/bash
CC=gcc
CFLAGS=-I$(IDIR) -static -static-libgcc -static-libstdc++ -lrt -pthread -Wl,--whole-archive -lpthread -Wl,--no-whole-archive -g -D __TEST__  -D_GNU_SOURCE
PROG_NAME := test_mltthrd

obj-y += $(PROG_NAME).o

test_mltthrd: $(obj-y)
	@mkdir -p bin
	@$(CC) -o bin/$@ $^ $(CFLAGS) $(LIBS)

clean:
	@rm -f *.o
	@rm -f bin/*

run: test_mltthrd
	@bin/test_mltthrd trace/uniPage_align4_tid0_r2w0.5 trace/uniPage_align4_tid2_r2w0.5 res/res0.txt res/res2.txt 1 1
	@python3 res/verify_res.py trace/uniPage_align4_tid0_r2w0.5 res/res0.txt_000
	@python3 res/verify_res.py trace/uniPage_align4_tid2_r2w0.5 res/res2.txt_000

run_full_verification:
	@number=0 ; while [[ $$number -le 9 ]] ; do \
		python3 res/verify_res.py trace/uniPage_align4_tid0_r2w0.5 res/res0.txt_00$$number & \
		python3 res/verify_res.py trace/uniPage_align4_tid2_r2w0.5 res/res2.txt_00$$number & \
		wait;\
        ((number = number + 1)) ; \
    done
	@number=10 ; while [[ $$number -le 19 ]] ; do \
		python3 res/verify_res.py trace/uniPage_align4_tid0_r2w0.5 res/res0.txt_0$$number & \
		python3 res/verify_res.py trace/uniPage_align4_tid2_r2w0.5 res/res2.txt_0$$number & \
		wait;\
        ((number = number + 1)) ; \
    done

run_multi_node1: test_mltthrd
	@bin/test_mltthrd trace/multiPage_align1024_tid0_r2w0.5 trace/multiPage_align1024_tid1_r2w0.5 res/res0.txt res/res1.txt 2 1
	@python3 res/verify_res.py trace/multiPage_align1024_tid0_r2w0.5 res/res0.txt
	@python3 res/verify_res.py trace/multiPage_align1024_tid1_r2w0.5 res/res1.txt

run_multi_node2: test_mltthrd
	@bin/test_mltthrd trace/multiPage_align1024_tid2_r2w0.5 trace/multiPage_align1024_tid3_r2w0.5 res/res2.txt res/res3.txt 2 2
	@python3 res/verify_res.py trace/multiPage_align1024_tid2_r2w0.5 res/res2.txt
	@python3 res/verify_res.py trace/multiPage_align1024_tid3_r2w0.5 res/res3.txt

run_uni_node1: test_mltthrd
	@bin/test_mltthrd trace/uniPage_align4_tid0_r2w0.5 trace/uniPage_align4_tid1_r2w0.5 res/res0.txt res/res1.txt 2 1
	@python3 res/verify_res.py trace/uniPage_align4_tid0_r2w0.5 res/res0.txt
	@python3 res/verify_res.py trace/uniPage_align4_tid1_r2w0.5 res/res1.txt

run_uni_node2: test_mltthrd
	@bin/test_mltthrd trace/uniPage_align4_tid2_r2w0.5 trace/uniPage_align4_tid3_r2w0.5 res/res2.txt res/res3.txt 2 2
	@python3 res/verify_res.py trace/uniPage_align4_tid2_r2w0.5 res/res2.txt
	@python3 res/verify_res.py trace/uniPage_align4_tid3_r2w0.5 res/res3.txt

run_uni_99_node1: test_mltthrd
	@bin/test_mltthrd trace/uniPage_align4_tid0_r2w0.99 trace/uniPage_align4_tid1_r2w0.99 res/res0.txt res/res1.txt 2 1
	@python3 res/verify_res.py trace/uniPage_align4_tid0_r2w0.99 res/res0.txt
	@python3 res/verify_res.py trace/uniPage_align4_tid1_r2w0.99 res/res1.txt

run_uni_99_node2: test_mltthrd
	@bin/test_mltthrd trace/uniPage_align4_tid2_r2w0.99 trace/uniPage_align4_tid3_r2w0.99 res/res2.txt res/res3.txt 2 2
	@python3 res/verify_res.py trace/uniPage_align4_tid2_r2w0.99 res/res2.txt
	@python3 res/verify_res.py trace/uniPage_align4_tid3_r2w0.99 res/res3.txt

run_uni_01_node1: test_mltthrd
	@bin/test_mltthrd trace/uniPage_align4_tid0_r2w0.01 trace/uniPage_align4_tid1_r2w0.01 res/res0.txt res/res1.txt 2 1
	@python3 res/verify_res.py trace/uniPage_align4_tid0_r2w0.01 res/res0.txt
	@python3 res/verify_res.py trace/uniPage_align4_tid1_r2w0.01 res/res1.txt

run_uni_01_node2: test_mltthrd
	@bin/test_mltthrd trace/uniPage_align4_tid2_r2w0.01 trace/uniPage_align4_tid3_r2w0.01 res/res2.txt res/res3.txt 2 2
	@python3 res/verify_res.py trace/uniPage_align4_tid2_r2w0.01 res/res2.txt
	@python3 res/verify_res.py trace/uniPage_align4_tid3_r2w0.01 res/res3.txt

generate_trace: clean_traces
	@cd trace && python3 genTrace.py
	@ls -l trace

clean_traces:
	@rm -f trace/multiPage*
	@rm -f trace/uniPage*
