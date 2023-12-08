#ifndef GETV
#define GETV

#include <stdio.h>
typedef unsigned char u8_t;
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
} vpak_t;
void printkey(u8_t *key);
u8_t *getRandomKey();
unsigned char *get_v_mod1();
unsigned char *get_v_mod2(int argc, char *argv[]);

#endif