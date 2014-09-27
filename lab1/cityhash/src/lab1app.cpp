#include <cstdio>
#include <iostream>
#include <string.h>
#include "city.h"
#include<unistd.h>
#include<fcntl.h>
#ifdef __SSE4_2__
#include "citycrc.h"
#endif

using std::cout;
using std::cerr;
using std::hex;
using std::dec;
using namespace std;

int main()
    {
        int fd = open("/dev/urandom", O_RDONLY);
        int len = 4096;
        char data[len];
        read(fd, &data, len);
        close(fd);
        clock_t start = clock();
        clock_t end = clock();
        int cycles = 0;
        for( float seconds = (float) (end-start)/CLOCKS_PER_SEC; seconds < 5; seconds = (float) (end-start)/CLOCKS_PER_SEC)
            {
            const uint128 u = CityHash128(data, len);
            cycles++;
            cout <<hex << Uint128Low64(u) << " " <<Uint128High64(u) <<" "<< cycles << " " << seconds <<endl;
            end=clock();
            }
        float seconds =  (float) (end-start)/CLOCKS_PER_SEC;
        cout << endl << seconds <<" Count of cycles "<< dec << cycles << endl;
    }
