#include "execval.h"
#include "cry.h"
#include "resprint.h"
typedef unsigned int u32_t;
/*
vpak:参数包
fp:输入文件
out:输出文件
key:初始密钥
r_buf:随机缓冲数组
mode:模式(加密/解密)
*/
typedef union {
  struct {
    FILE *fp, *out;
    u8_t *key;
    u8_t r_buf[256];
    char mode;
  };
  u8_t buf[512];
} pakout_t;
/*
over:关闭文件并释放空间
v1:传入的参数包
*/
static void over(pakout_t v1) {
  if (v1.fp != NULL)
    fclose(v1.fp);
  if (v1.out != NULL)
    fclose(v1.out);
}
/*
接口函数
exec_val:根据传入的参数包执行相应操作
vals:传入的参数包
return:返回是否成功执行
*/
bool exec_val(unsigned char *v) {
  clock_t cl1 = clock();
  pakout_t vals;
  memcpy(vals.buf, v, 512);
  u32_t res = 0;
  runcrypt runner(vals.fp, vals.out, vals.key);
  if (vals.fp == NULL)
    return printinv(0);
  clock_t totalTime = 0;
  if (vals.mode == 'e' || vals.mode == 'E') {
    runner.enc(vals.r_buf);
    printenc();
  } else if (vals.mode == 'd' || vals.mode == 'D') {
    res = runner.dec();
    printres(res);
  } else if (vals.mode == 'v') {
    res = runner.verify();
    printres(res);
  }
  clock_t cl2 = clock();
  printtime(cl2 - cl1, multicry_master::THREADS_NUM);
  over(vals);
  return res == 0;
}