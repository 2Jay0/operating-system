#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  int n;
  int a,b,c;

  n = atoi(argv[1]);
  a = atoi(argv[2]);
  b = atoi(argv[3]);
  c = atoi(argv[4]);
  printf("%d ",fibonacci(n));
  printf("%d\n",max_of_four_int(n,a,b,c));

  return EXIT_SUCCESS;
}
