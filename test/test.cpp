#include "cry.h"
#include "getval.h"
#include "valhelper.h"
#include "testutil.h"

#include <stdio.h>
#include <string.h>
#include <chrono>
#include <cstdio>

/*
exec:以给定命令行参数驱动一次加解密流程(进程内复用 runcrypt)
argc/argv:命令行参数
return:成功返回 true,失败返回 false
*/
bool exec(int argc, char *argv[]) {
  // 初始化
  srand(time(NULL));
  unsigned char *vals = NULL;
  // 获取参数

  if (argc == 1)
    vals = get_v_mod1();
  else
  {
    vals = get_v_opt(argc, argv);
    WencryInformation wif;
    if (vals == NULL)
      return false;
    if (((vpak_t *)vals)->mode == 'V')
    {
      strlog("Kernel version", wif.get_version());
      strlog("Build time", wif.get_buildtime());
      return true;
    }
    else if (((vpak_t *)vals)->mode == 'h')
    {
      std::cout<<wif.get_help();
      return true;
    }
  }
  Settings settings(((vpak_t *)vals)->ctype, ((vpak_t *)vals)->htype, ((vpak_t *)vals)->no_echo);
  // 执行任务
  runcrypt *runner = runcrypt_create(((vpak_t *)vals)->fp, ((vpak_t *)vals)->out, ((vpak_t *)vals)->key, settings);
  try{
    switch (getProcessMode(((vpak_t *)vals)->mode))
    {
      case 0:
        runner->execute_encrypt(((vpak_t *)vals)->size, ((vpak_t *)vals)->r_buf, ((vpak_t *)vals)->r_len);
        break;
      case 1:
        runner->execute_decrypt(((vpak_t *)vals)->size);
        break;
      case 2:
        runner->execute_verify(((vpak_t *)vals)->size);
        break;
      default:
        runcrypt_destroy(runner);
        return false;
        break;
    }
  }
  catch(const char *errlog){
    runcrypt_destroy(runner);
    std::cout<<"Error occured:"<<errlog<<std::endl;
    return false;
  }
  catch(std::string errlog){
    runcrypt_destroy(runner);
    std::cout<<"Error occured:"<<errlog<<std::endl;
    return false;
  }
  runcrypt_destroy(runner);
  return true;
}
#define BUFFER_SIZE 0x10000
/*
cmp_file:逐块比较两个文件内容是否一致
x:文件1(函数会关闭)
y:文件2(函数会关闭)
return:一致返回1,不一致返回0
*/
int cmp_file(FILE *x, FILE *y) {
  unsigned char buffer1[BUFFER_SIZE + 2], buffer2[BUFFER_SIZE + 2];
  int read1, read2;
  int flag = 0;
  int cnt = 0;
  while (1) {
    memset(buffer1, 0, BUFFER_SIZE + 2);
    memset(buffer2, 0, BUFFER_SIZE + 2);
    read1 = fread(buffer1, 1, BUFFER_SIZE, x);
    read2 = fread(buffer2, 1, BUFFER_SIZE, y);
    flag = (read1 == read2) && (memcmp(buffer1, buffer2, read1) == 0);
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
/*
makeFullTest:对字符串str执行"加密->解密->比对"完整往返测试
str:测试内容
type:type低4位=加密模式,高4位=哈希模式
return:往返一致返回1,失败返回0
*/
int makeFullTest(const char *str, u8_t type) {
  char fname[128], fwenc[160], fout[160];
  make_tmp_name(fname, sizeof(fname), "ft");
  snprintf(fwenc, sizeof(fwenc), "%s.wenc", fname);
  snprintf(fout, sizeof(fout), "%s.out", fname);
  FILE *fp = fopen(fname, "wb");
  fwrite(str, 1, strlen(str), fp);
  fclose(fp);
  char name[] = "./wencry";
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
  if (!exec(10, (char **)argv1)) {
    remove(fname);
    return 0;
  }
  char *argv2[] = {name, dflg, iflg, fwenc, kflg, key, oflg, fout};
  if (!exec(8, (char **)argv2)) {
    remove(fname);
    remove(fwenc);
    return 0;
  }
  FILE *f1 = fopen(fname, "rb");
  FILE *f2 = fopen(fout, "rb");
  int r = cmp_file(f1, f2);
  remove(fname);
  remove(fwenc);
  remove(fout);
  return r;
}
/* buf:约32MB全局测试缓冲(供 makeBigTest 使用,末尾预留字节用于越界检测) */
char buf[0x2000010];
/*
makeBigTest:对约32MB大文件进行往返测试
offset:文件末尾置0的偏移位置
type:type低4位=加密模式,高4位=哈希模式
return:往返一致返回1,失败返回0
*/
int makeBigTest(int offset, u8_t type = 0) {
  srand(time(NULL));
  memset(buf, 'a', sizeof(buf));
  buf[0x2000000 + offset] = 0;
  return makeFullTest(buf, type);
}
/*
makeSpeedTest:测量指定加密模式的加密吞吐量
type:加密模式
return:成功返回吞吐量(MB/s),失败返回0
*/
double makeSpeedTest(u8_t type) {
  char fname[128], fwenc[160], ctype[32];
  make_tmp_name(fname, sizeof(fname), "spd");
  snprintf(fwenc, sizeof(fwenc), "%s.wenc", fname);
  const size_t SIZE = (size_t)32 * 1024 * 1024 + 16;
  FILE *fp = fopen(fname, "wb");
  if (fp == NULL)
    return 0;
  unsigned char b[4096];
  size_t left = SIZE, off = 0;
  while (left) {
    size_t n = left < sizeof(b) ? left : sizeof(b);
    for (size_t i = 0; i < n; ++i)
      b[i] = (unsigned char)((off + i) % 251);
    fwrite(b, 1, n, fp);
    off += n;
    left -= n;
  }
  fclose(fp);
  char name[] = "./wencry";
  char key[] = "ABEiM0RVZneImaq7zN3u/w==";
  char eflg[] = "-e";
  char iflg[] = "-i";
  char oflg[] = "-o";
  char kflg[] = "-k";
  char mflg[] = "--cmode";
  char nflg[] = "-n";
  sprintf(ctype, "%d", type);
  char *argv1[] = {name, eflg, iflg, fname, oflg, fwenc, mflg, ctype, kflg, key, nflg};
  auto t0 = std::chrono::steady_clock::now();
  bool ok = exec(11, (char **)argv1);
  auto t1 = std::chrono::steady_clock::now();
  double secs = std::chrono::duration<double>(t1 - t0).count();
  double mbs = (secs > 0) ? (double)SIZE / 1e6 / secs : 0;
  printf("Encrypt throughput: %.2f MB/s\n", mbs);
  remove(fname);
  remove(fwenc);
  return ok ? mbs : 0;
}