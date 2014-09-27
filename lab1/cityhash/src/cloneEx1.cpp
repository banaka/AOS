#include <sys/wait.h>
#include <sys/utsname.h>
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <fcntl.h>

using namespace std;
using std::cout;
using std::cerr;
using std::hex;
using std::dec;


int variable, fd;
using namespace std ;
int do_something(void *) {
variable = 42;
cout << "sana" << endl ;
close(fd);
_exit(0);
}

int main() {
char tempch;

variable = 9;
fd = open("test.file", O_RDONLY);

int size_of_stack = 8192; 
void *child_stack = ::operator new(size_of_stack);

clone(do_something, (char*)child_stack+size_of_stack ,CLONE_VM|CLONE_FILES, NULL);
sleep(1);

printf("The variable is now %d\n", variable);
if (read(fd, &tempch, 1) < 1) {
  perror("File Read Error");
  exit(1);
}
printf("We could read from the file\n");
return 0;
}
