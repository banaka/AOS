all: clean test loader

clean:
	-rm test loader

test: test3.c
	gcc -static -Wl,-Ttext-segment=2000000 -o test test3.c

loader: loader.c
	gcc -static -g -w -Wall -o loader loader.c -ldl -lelf
