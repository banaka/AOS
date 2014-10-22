all: clean test loader

clean:
	rm test
	rm loader

test: test3.c
	gcc -static -Wl,-Ttext-segment=2000000 -o test test3.c

loader: loader_ak.c
	gcc -g -w -Wall -o loader loader_ak.c -ldl -l elf
