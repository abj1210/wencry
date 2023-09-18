#include <stdio.h>
#include <string.h>
#define BUFFER_SIZE 1024
int cmp_file(FILE *x, FILE *y) {
  unsigned char buffer1[BUFFER_SIZE], buffer2[BUFFER_SIZE];
  int read1, read2;
  int flag = 0;
  while (1) {
    memset(buffer1, 0, BUFFER_SIZE);
    memset(buffer2, 0, BUFFER_SIZE);
    read1 = fread(buffer1, 1, BUFFER_SIZE, x);
    read2 = fread(buffer2, 1, BUFFER_SIZE, y);
    printf("%s\n%s\n", buffer1, buffer2);
    flag = (read1 == read2) && (strcmp(buffer1, buffer2) == 0);
    if (read1 != BUFFER_SIZE)
      break;
  }
  fclose(x);
  fclose(y);
  return flag;
}

int main(int argc, char *argv[]) {
  if (argc != 3)
    return 1;
  FILE *f1, *f2;
  f1 = fopen(argv[1], "rb");
  f2 = fopen(argv[2], "rb");
  if (cmp_file(f1, f2)) {
    printf("Files check OK!\n");
    return 0;
  } else {
    printf("Files check fail!\n");
    return -1;
  }
}