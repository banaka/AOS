#include <sys/wait.h>
#include <sys/utsname.h>
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <fcntl.h>
#include <cstdlib>
#include <cstdio>
#include "city.h"
#ifdef __SSE4_2__
#include "citycrc.h"
#endif

using namespace std;
using std::cout;
using std::cerr;
using std::hex;
using std::dec;

int variable, fd;
int len = 4096;
char data[4096];
bool active = false;

int hashFunc(void *) {
    while(!active){
        cout << "..." ;
    }
    clock_t start = clock();
    clock_t end = clock();
    int cycles = 0;
    for( float seconds = (float) (end-start)/CLOCKS_PER_SEC; seconds < 5; seconds = (float) (end-start)/CLOCKS_PER_SEC) {
            const uint128 u = CityHash128(data, len);
            cycles++;
            end=clock();
        }
    float seconds =  (float) (end-start)/CLOCKS_PER_SEC;
    cout << endl << seconds <<" Count of cycles "<< dec << cycles << endl;
    _exit(0);
}

int main(int argc, char* argv[]) {
    char tempch;
    variable = 9;
    fd = open("/dev/urandom", O_RDONLY);
    char data[len];
    read(fd, &data, len);
    close(fd);

    int size_of_stack = 8192; 
    void *child_stack ;

    if (argc > 1){
        int no=atoi(argv[1]);
        cout<<no<<endl;
        for(int i=0; i < no ; i++){
            child_stack = ::operator new(size_of_stack);
            clone(hashFunc, (char*)child_stack+size_of_stack ,CLONE_VM|CLONE_FILES, NULL);
        }
        //sleep(5);
        active = true;
    }else{
        active = true;
        hashFunc( 0 );    
    }
    return 0;
}
