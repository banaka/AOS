#include <unistd.h>
#include <iostream>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <ctime>
#include <chrono>

using std::cout;
using std::endl;

#define SIZE 4096

static const char* path = "/u/bansal/AOS/test/file.txt";
int main(int argc, char *argv[]) {
	
	using namespace std::chrono;
	high_resolution_clock::time_point start, end, opentime, readtime, writetime ;

 	int fd = open("/dev/urandom", O_RDONLY);
	char buffer[SIZE];
	int count = read(fd, &buffer, SIZE);
	close(fd);
        
	fd = open(path, O_RDWR);
	count = write(fd, &buffer, SIZE);
	close(fd);


	int opens = atoi(argv[1]);
	int writes = atoi(argv[2]);
	int reads = atoi(argv[3]);
	count = 0;
 
	start = high_resolution_clock::now();
	for (int i = 0; i < (opens - 1); ++i) {
		fd = open(path, O_RDWR);
		if (!fd)
			perror("Open file");
		close(fd);
	}  
	opentime = high_resolution_clock::now();
	for (int i = 0; i < writes; ++i) { 
		fd = open(path, O_RDWR);
		if (!fd)
			perror("Open for Writing");

		count = write(fd, &buffer, SIZE);	
		if (count != SIZE)
			perror("Write Error");
		close(fd);
	}
	writetime = high_resolution_clock::now();
	for(int  i=0; i < reads; i++) {
	        fd = open(path, O_RDWR);
                if (!fd)
                        perror("Open for Reading");

                count = read(fd, &buffer, SIZE);
                if (count != SIZE)
                        perror("small write Error");
                close(fd);
	}
	readtime = high_resolution_clock::now();
	end = high_resolution_clock::now();
	auto time_taken = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
	cout << "total time "<<   time_taken<<" ms" << endl;

	time_taken = std::chrono::duration_cast<std::chrono::milliseconds>(readtime - writetime).count();
        cout << "total read time "<<   time_taken<<" ms" << endl;

	time_taken = std::chrono::duration_cast<std::chrono::milliseconds>(writetime - opentime).count();
        cout << "total write time "<<   time_taken<<" ms" << endl;

	time_taken = std::chrono::duration_cast<std::chrono::milliseconds>(opentime - start).count();
        cout << "total open time "<<   time_taken<<" ms" << endl;

	return 0;
}

