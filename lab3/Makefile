all: clean test loader demand_loader

clean:
	-rm test loader demand

test: test.c
	gcc -static -Wl,-Ttext-segment=2000000 -o test test.c

loader: loader.c
	gcc -static -Wall -I /u/bansal/modules/install/include/  -L /u/bansal/modules/install/lib/  -o loader loader.c -lelf -ldl -w

demand_loader: demand_loader.c
	gcc -static -Wall -I /u/bansal/modules/install/include/  -L /u/bansal/modules/install/lib/  -o demand demand_loader.c -lelf -ldl -w
	#gcc -static -g -w -Wall -o loader loader.c -ldl -lelf
