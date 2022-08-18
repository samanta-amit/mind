CXX := g++
PROGRAM := tcp_server

build: tcp_server.cpp tcp_server.hpp ufutex_disagg.hpp lock_free_queue.hpp
	$(CXX) tcp_server.cpp -o $(PROGRAM) -g -lpthread

run: build
	./$(PROGRAM)

clean:
	rm $(PROGRAM)