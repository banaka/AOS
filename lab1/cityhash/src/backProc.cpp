#include <sys/wait.h>
//#include <sys/utsname.h>
#include <sched.h>
//#include <string.h>
#include <stdlib.h>
//#include <unistd.h>
#include <iostream>
#include <fcntl.h>
//#include <cstdlib>
//#include <cstdio>
//#include <time.h>
#include <sys/time.h>
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

int len = 4096;
char data[4096];
volatile bool active = false;
int loopCount = 400000;
int core_count , curr_core; 

//Function to Calculate the Time taken for a given set of cycles 
int hashFunc(void *) {
    while(!active){
    }

    int cycles = 0;
    struct timeval start,end;
    gettimeofday(&start, NULL); 
    //std::chorno::steady_clock::time_point start = std::chrono::steady_clock::now(); 
    //double start = clock();
    for(int i = 0; i < loopCount ;++i){
            const uint128 u = CityHash128(data, len);
            cycles++;
        }
    //double seconds = (clock() - start);
    //cout << endl << "Count of Cycles" << dec << cycles << endl;
    //std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    //std::chrono::stady_Clock::time_point seconds = end - start; 
    //cout << endl <<"Count of cycles "<< dec << cycles << " took time "<< std::chorono::duration_cast<std::chrono::microseconds>(end-start).count() << endl;
    gettimeofday(&end, NULL);
    float millisec = (float) (end.tv_sec - start.tv_sec) + ((float)(end.tv_usec - start.tv_usec))/ 1000000.0;
    cout << "time taken " << millisec<< endl; 

    return(EXIT_SUCCESS);
}


//Function to Calcuate the No of cycles in a given time (5 Seconds) 
int hashFuncTimeBound(void *) {
    while(!active){
    }
    int cycles = 0;
    for( time_t end = time(NULL)+5; time(NULL) < end;){
            const uint128 u = CityHash128(data, len);
            cycles++;
        }
    cout << "Count of Cycles " << dec << cycles << endl;
    return(EXIT_SUCCESS);
}
//Function for Setting Scheduler Affinity 
void set_sech_affinity( int procId){
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(curr_core,&mask);
    int value = sched_setaffinity(procId, sizeof(mask), &mask);
    cout << "sched_affinity: " << value << " set for Core " << curr_core << endl;
    curr_core++;
    if(curr_core == core_count)
        curr_core = 0;
    return;
}


//Function to for Cgroup 
void set_cgroup( int procId){
    string cmd = "echo " ;
    cmd.append(std::to_string(procId));
    cmd = cmd + ">> /sys/fs/cgroup/lab/tasks";
    const char *constCmd = cmd.c_str();
    cout<< endl << constCmd << endl;
    system(constCmd);
}

int main(int argc, char* argv[]) {
    int fd = open("/dev/urandom", O_RDONLY);
    char data[len];
    read(fd, &data, len);
    close(fd);
    
    struct sched_param param;
    param.sched_priority = 99;
    core_count = sysconf(_SC_NPROCESSORS_CONF);

    setenv("LD_BIND_NOW","1",true);

    int size_of_stack = 2 * len; 
    //void *child_stack ;

    if (argc == 6){
        int procC = atoi(argv[1]);//Count of the Clone Processes
        int backC = atoi (argv[2]);//Count of the background process
        if (backC > 0){ 
            start(atoi(argv[2]));
        }
        int procIds[procC]; //Array To keep the Processid's of the Clone Processes 
        //Call to hashFunction if 5th argv is 0  
        if( atoi(argv[5]) == 0 ){ 
            curr_core = 0;
            active = false;
            for(int i = 0; i < procC ; i++){
                void *child_stack = ::operator new(size_of_stack);
                procIds[i] = clone(hashFunc, (char*)child_stack+size_of_stack , CLONE_VM|SIGCHLD|CLONE_FS|CLONE_FILES, NULL);
                 // sched_getparam(procIds[i], &param); 
                 // param.sched_priority = 99;
                 sched_setscheduler(procIds[i], SCHED_RR, &param); 

                if ( atoi(argv[3]) == 1 ){
                    set_sech_affinity(procIds[i]);
                } 
                if (atoi(argv[4]) == 1){
                    set_cgroup(procIds[i]);
                }

             }
             //cout << system("cat /sys/fs/cgroup/lab/tasks") << endl;
             active = true;
             for(int i=0; i< procC; i++){
                while( -1 != waitpid(procIds[i], NULL, WNOHANG | WUNTRACED )) 
                ;
                //cout<< "Clone:"<< procIds[i] << " ended"<< endl; 
            }
        }else {
            curr_core = 0;
            active = false;
            for(int i = 0; i < procC ; i++){
                void *child_stack = ::operator new(size_of_stack);
                procIds[i] = clone(hashFuncTimeBound, (char*)child_stack+size_of_stack , CLONE_VM|SIGCHLD, NULL);

                if ( atoi(argv[3]) == 1 ){
                    set_sech_affinity(procIds[i]);
                }
                if (atoi(argv[4]) == 1){
                    set_cgroup(procIds[i]);
                }

             }
             cout << system("cat /sys/fs/cgroup/lab/tasks") << endl;
             active = true;
             for(int i=0; i< procC; i++){
                while( -1 != waitpid(procIds[i], NULL, WNOHANG | WUNTRACED ))
                ;
                cout<< "Clone:"<< procIds[i] << " ended"<< endl;
            }

	}


        if ( backC > 0) 
            stop();
    }else{
        active = true;
        hashFuncTimeBound( 0 );    
    }
    return 0;
}
