#include <stdlib.h>
#include <sys/shm.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/sched.h> 
 
int i;
int ppid, pid;
int **child_stack;
int counter;
int num_of_process;
 
 
void process1() {
    pid=getpid();
    ppid=getppid();
    printf("PID(child of a child) =  %d \nPPID(child of a child) = %d \n",pid, ppid);
    _exit(0);
}
 
 
void process(int j) {
    pid=getpid();
    ppid=getppid();
    printf("PID =  %d \nPPID = %d \n",pid, ppid);
    for(counter=0; counter<j;counter++) {
        clone(process1, child_stack, CLONE_VFORK, NULL);
    }
    _exit(0);           
}           
 
 
int main(int argc, char** argv)
{
 
 
    if (argc < 2) {
        printf("To few parameters\n");
        exit(0);
    }
    child_stack = (void **) malloc(16384) + 16384 / sizeof (*child_stack);
    num_of_process=atoi(argv[1]);
        for(i=1; i<=num_of_process; i++)
        {
            clone(process, child_stack, CLONE_VFORK, i);
 
 
        }
 
 
    exit(0);
}
