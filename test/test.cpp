#include "cry.h"
#include "getval.h"

#include <stdio.h>
#include <string.h>
#define BUFFER_SIZE 0x10000
int cmp_file(FILE *x, FILE *y) {
  char buffer1[BUFFER_SIZE + 2], buffer2[BUFFER_SIZE + 2];
  int read1, read2;
  int flag = 0;
  int cnt = 0;
  while (1) {
    memset(buffer1, 0, BUFFER_SIZE + 2);
    memset(buffer2, 0, BUFFER_SIZE + 2);
    read1 = fread(buffer1, 1, BUFFER_SIZE, x);
    read2 = fread(buffer2, 1, BUFFER_SIZE, y);
    flag = (read1 == read2) && (strcmp(buffer1, buffer2) == 0);
    if(!flag){
      printf("A%d-%d:%s\nB%d-%d:%s\n", cnt, read1, buffer1, cnt, read2, buffer2);
    }
    cnt++;
    if ((!flag) || feof(x))
      break;
  }
  fclose(x);
  fclose(y);
  if (flag)
    return 1;
  else
    return 0;
}
int makeFullTest(const char *str, u8_t type) {
  FILE *fp = fopen("test.txt", "w");
  fwrite(str, 1, strlen(str), fp);
  fclose(fp);
  char name[] = "./wencry";
  char fname[] = "test.txt";
  char fwenc[] = "test.txt.wenc";
  char fout[] = "test.out";
  char eflg[] = "-e";
  char dflg[] = "-d";
  char iflg[] = "-i";
  char oflg[] = "-o";
  char kflg[] = "-k";
  char mflg[] = "--cmode";
  char hflg[] = "--hmode";
  char ctype[100], htype[100];
  sprintf(ctype, "%d", type&0xf);
  sprintf(htype, "%d", (type>>4)&0xf);
  char key[] = "ABEiM0RVZneImaq7zN3u/w==";
  char *argv1[] = {name, eflg, iflg, fname, mflg, ctype, hflg, htype, kflg, key};
  runcrypt runner1(get_v_opt(10, (char **)argv1));
  if (!runner1.exec_val())
    return 0;
  char *argv2[] = {name, dflg, iflg, fwenc, mflg, ctype, hflg, htype, kflg, key, oflg, fout};
  runcrypt runner2(get_v_opt(12, (char **)argv2));
  if (!runner2.exec_val())
    return 0;
  FILE *f1 = fopen(fname, "rb");
  FILE *f2 = fopen(fout, "rb");
  return cmp_file(f1, f2);
}
char buf[0x2000010];
int makeBigTest(int offset, u8_t type = 0) {
  srand(time(NULL));
  memset(buf, 'a', sizeof(buf));
  buf[0x2000000 + offset] = 0;
  return makeFullTest(buf, type);
}
int makeSpeedTest(u8_t type = 1) {
  char name[] = "./wencry";
  char fname[] = "test.txt";
  char key[] = "ABEiM0RVZneImaq7zN3u/w==";
  char eflg[] = "-e";
  char iflg[] = "-i";
  char kflg[] = "-k";
  char mflg[] = "--cmode";
  char ctype[100];
  sprintf(ctype, "%d", type);
  char *argv1[] = {name, eflg, iflg, fname, mflg, ctype, kflg, key};
  runcrypt runner(get_v_opt(8, (char **)argv1));
  if (!runner.exec_val())
    return 0;
  else
    return 1;
}