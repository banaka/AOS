#include <stdio.h>

int main(int argc, char** argv)
{
    fprintf(stdout, "Hello world! argc=%d argv = %s", argc, argv[1]);
    return 0;
}

