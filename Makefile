iterative: 01_iterative/main.c
                gcc -o $@ $<

forking: 02_forking/main.c
                gcc -o $@ $<

preforked: 03_preforked/main.c
                gcc -o $@ $<

threaded: 04_threaded/main.c
                gcc -o $@ $< -lpthread

prethreaded: 05_prethreaded/main.c
                gcc -o $@ $< -lpthread

poll: 06_poll/main.c
                gcc -o $@ $<

epoll: 07_epoll/main.c
                gcc -o $@ $<

mpsc.o: 08_liburing_threaded/mpsc.c 08_liburing_threaded/mpscq.h
                gcc -g -c 08_liburing_threaded/mpsc.c mpsc.o

libmpscq.a: mpsc.o
                ar -cvq libmpscq.a mpsc.o

liburing_threaded: 08_liburing_threaded/main.c libmpscq.a
                gcc -g -o $@ $< -L ./ -lpthread -luring -lmpscq

liburing: 09_liburing/main.c
                gcc -g -o $@ $< -lpthread -luring

all: iterative forking preforked threaded prethreaded poll epoll libmpscq.a liburing_threaded liburing

.PHONY: clean

clean:
        rm -f iterative forking preforked threaded prethreaded poll epoll libmpscq.a liburing liburing_threaded
