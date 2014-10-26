#include <stdio.h>
#include <sys/mman.h>

int gb;
int main()
{
  gb = 1;
  printf("gb = %d\n", gb);
  return 0;
}
