#include<unistd.h>
#include<fcntl.h>
int main()
            {
                int fd = open("/dev/urandom", O_RDONLY);
                char data[4096];
                read(fd, &data, 4096);
                close(fd);
                fd = open("/dev/null", O_WRONLY);
                write(fd, &data, 4096);
                close(fd);
            }
