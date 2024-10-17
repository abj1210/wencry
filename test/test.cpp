#include "cry.h"
#include "getval.h"

#include <stdio.h>
#include <string.h>

bool exec(int argc, char *argv[]) {
  //初始化
  unsigned char *vals = NULL;
  //获取参数
  if (argc == 1)
    vals = get_v_mod1();
  else {
    vals = get_v_opt(argc, argv);
    if(vals == NULL)
      return false;
    if(((vpak_t *)vals)->mode == 'V'){
      version();
      return true;
    }
    else if(((vpak_t *)vals)->mode == 'h'){
      help();
      return true;
    }
  }
  Settings settings;
  settings.set_ctype(((vpak_t *)vals)->ctype);
  settings.set_htype(((vpak_t *)vals)->htype);
  settings.set_no_echo(((vpak_t *)vals)->no_echo);
  bool flag;
  //执行任务
  runcrypt runner(((vpak_t *)vals)->fp, ((vpak_t *)vals)->out, ((vpak_t *)vals)->key, settings);
  if(((vpak_t *)vals)->mode == 'e' || ((vpak_t *)vals)->mode == 'E')
    flag = runner.execute_encrypt(((vpak_t *)vals)->size, ((vpak_t *)vals)->r_buf);
  else if(((vpak_t *)vals)->mode == 'd' || ((vpak_t *)vals)->mode == 'D')
    flag = runner.execute_decrypt(((vpak_t *)vals)->size);
  else if(((vpak_t *)vals)->mode == 'v')
    flag = runner.execute_verify(((vpak_t *)vals)->size);
  else 
    return false;
  return flag;
}
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
  if (!exec(10, (char **)argv1))
    return 0;
  char *argv2[] = {name, dflg, iflg, fwenc, mflg, ctype, hflg, htype, kflg, key, oflg, fout};
  if (!exec(12, (char **)argv2))
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
  if (!exec(8, (char **)argv1))
    return 0;
  else
    return 1;
}