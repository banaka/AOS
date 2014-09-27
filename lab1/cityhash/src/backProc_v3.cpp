#include <sys/wait.h>
#include <sys/utsname.h>
#include <sched.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <fcntl.h>
#include <cstdlib>
#include <cstdio>
#include <time.h>
#include "backgroundTask.h"
#include "city.h"
#ifdef __SSE4_2__
#include "citycrc.h"
#endif


using namespace std;
using std::cout;
using std::cerr;
using std::hex;
using std::dec;

int fd;
int len = 4096;
char data[4096];
volatile bool active = false;

int hashFunc(void *) {
    while(!active){
        //cout << "..." ;
    }
    //system("echo $pid >> /sys/fs/cgroup/lab/tasks");

    int cycles = 0;
/*
*/
    //for( time_t end = time(NULL)+5; time(NULL) < end;){
    for(int i = 0; i < 1000000 ;++i){

            const uint128 u = CityHash128(data, len);
            cycles++;
        }
    cout << endl <<" Count of cycles "<< dec << cycles << endl;
    return(EXIT_SUCCESS);
}

int main(int argc, char* argv[]) {
    fd = open("/dev/urandom", O_RDONLY);
    char data[len];
    read(fd, &data, len);
    close(fd);

    int coreCount = sysconf(_SC_NPROCESSORS_CONF);
    int curr_core = 0;

    setenv("LD_BIND_NOW","1",true);
    //putenv("LD_BIND_NOW=1");

    int size_of_stack = 8192; 
    void *child_stack ;

    if (argc == 5){
        int no = atoi(argv[1]);
        //cout << no << endl;
        start(atoi(argv[2]));
        int procIds[no]; 
        for(int i=0; i < no ; i++){
            child_stack = ::operator new(size_of_stack);
           procIds[i] = clone(hashFunc, (char*)child_stack+size_of_stack ,CLONE_VM|SIGCHLD, NULL);

            if ( atoi(argv[3]) == 1 ){
                cpu_set_t mask;
                CPU_ZERO(&mask);
                CPU_SET(curr_core,&mask);
                int value = sched_setaffinity(procIds[i], sizeof(mask), &mask);
                cout << "sched_affinity: " << value << " set for Core " << curr_core << endl;
                curr_core++;
                if(curr_core == coreCount)
                   curr_core = 0;
            } 
            if (atoi(argv[4]) == 1){//char buffer[100] = o;
                string cmd = "echo " ;
                cmd.append(std::to_string(procIds[i]));
                cmd = cmd + ">> /sys/fs/cgroup/lab/tasks";
                const char *constCmd = cmd.c_str();
                cout<< endl << constCmd << endl; 
                system(constCmd);
             }
        }
        cout << system("cat /sys/fs/cgroup/lab/tasks") << endl;
        active = true;
        //sleep(3);
        for(int i=0; i< no; i++){
            while( -1 != waitpid(procIds[i], NULL, WNOHANG | WUNTRACED )) 
                ;
            cout<< "Clone:"<< procIds[i] << " ended"<< endl; 
        }
        stop();
    }else{
        active = true;
        hashFunc( 0 );    
    }
    return 0;
}
