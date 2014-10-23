all: clean test loader

clean:
	-rm test loader

test: test3.c
	gcc -static -Wl,-Ttext-segment=2000000 -o test test3.c

loader: loader.c
	gcc -static -Wall  -I /u/bansal/modules/install/include/  -L /u/bansal/modules/install/lib/  -o loader loader.c -lelf -ldl -w
	#gcc -static -g -w -Wall -o loader loader.c -ldl -lelf
