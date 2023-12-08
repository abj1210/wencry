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
typedef struct {
  FILE *fp, *out;
  u8_t *key;
  u8_t r_buf[256];
  char mode;
} pakout_t;
/*
over:关闭文件并释放空间
v1:传入的参数包
*/
static void over(pakout_t *v1) {
  delete[] v1->key;
  if (v1->fp != NULL)
    fclose(v1->fp);
  if (v1->out != NULL)
    fclose(v1->out);
  delete v1;
}
/*
encrypt: 根据传入的参数包设置加密参数并运行加密程序
v1: 传入的参数包
reutrn: 操作时间
*/
static clock_t encrypt(pakout_t *v1) {
  clock_t cl1 = clock();
  enc(v1->fp, v1->out, v1->r_buf, v1->key);
  clock_t cl2 = clock();
  printenc();
  return cl2 - cl1;
}
/*
decrypt: 根据传入的参数包设置加密参数并运行解密程序
v1: 传入的参数包
reutrn: 操作时间
*/
static clock_t decrypt(pakout_t *v1) {
  clock_t cl1 = clock();
  int res = dec(v1->fp, v1->out, v1->key);
  clock_t cl2 = clock();
  printres(res);
  return cl2 - cl1;
}
/*
verify: 根据传入的参数包验证密钥和文件
v1: 传入的参数包
reutrn: 操作时间
*/
static clock_t get_verify(pakout_t *v1) {
  clock_t cl1 = clock();
  int res = verify(v1->fp, v1->key);
  clock_t cl2 = clock();
  printres(-res);
  return cl2 - cl1;
}
/*
接口函数
exec_val:根据传入的参数包执行相应操作
vals:传入的参数包
return:返回是否成功执行
*/
bool exec_val(unsigned char *v) {
  pakout_t *vals = (pakout_t *)v;
  if (vals->fp == NULL)
    return printinv(0);
  clock_t totalTime = 0;
  if (vals->mode == 'e' || vals->mode == 'E')
    totalTime = encrypt(vals);
  else if (vals->mode == 'd' || vals->mode == 'D')
    totalTime = decrypt(vals);
  else if (vals->mode == 'v')
    totalTime = get_verify(vals);
  printtime(totalTime, THREADS_NUM);
  over(vals);
  return true;
}