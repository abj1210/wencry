#include "execval.h"
#include "getval.h"

#include <stdio.h>
#include <string.h>
#define BUFFER_SIZE 0x10000
int cmp_file(FILE *x, FILE *y) {
  char buffer1[BUFFER_SIZE + 2], buffer2[BUFFER_SIZE + 2];
  int read1, read2;
  int flag = 0;
  while (1) {
    memset(buffer1, 0, BUFFER_SIZE + 2);
    memset(buffer2, 0, BUFFER_SIZE + 2);
    read1 = fread(buffer1, 1, BUFFER_SIZE, x);
    read2 = fread(buffer2, 1, BUFFER_SIZE, y);
    flag = (read1 == read2) && (strcmp(buffer1, buffer2) == 0);
    if ((!flag) || read1 != BUFFER_SIZE)
      break;
  }
  fclose(x);
  fclose(y);
  if (flag)
    return 1;
  else
    return 0;
}
int makeFullTest(const char *str, u8_t type = 0) {
  FILE *fp = fopen("test.txt", "w");
  fwrite(str, 1, strlen(str), fp);
  fclose(fp);
  char name[] = "./wencry";
  char fname[] = "test.txt";
  char fwenc[] = "test.txt.wenc";
  char fout[] = "test.out";
  char enc[] = "-e", dec[] = "-d";
  char ctype[100];
  sprintf(ctype, "%d", type);
  char key[] = "ABEiM0RVZneImaq7zN3u/w==";
  char *argv1[] = {name, enc, fname, ctype, key};
  int argc = 5;
  if (!exec_val(get_v_mod2(argc, (char **)argv1)))
    return 0;
  char *argv2[] = {name, dec, fwenc, ctype, key, fout};
  argc = 6;
  if (!exec_val(get_v_mod2(argc, (char **)argv2)))
    return 0;
  FILE *f1 = fopen(fname, "rb");
  FILE *f2 = fopen(fout, "rb");
  return cmp_file(f1, f2);
}
char buf[0x2000010];
int makeBigTest(int offset, u8_t type = 0) {
  memset(buf, '0', sizeof(buf));
  buf[0x2000000 + offset] = 0;
  return makeFullTest(buf, type);
}
int makeSpeedTest(u8_t type = 0) {
  char name[] = "./wencry";
  char fname[] = "test.txt";
  char enc[] = "-e";
  char key[] = "ABEiM0RVZneImaq7zN3u/w==";
  char ctype[100];
  sprintf(ctype, "%d", type);
  char *argv1[] = {name, enc, fname, ctype, key};
  int argc = 5;
  if (!exec_val(get_v_mod2(argc, (char **)argv1)))
    return 0;
  else
    return 1;
}