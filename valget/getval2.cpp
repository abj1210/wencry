#include "base64.h"
#include "getval.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
/*
getArgsFilep:从参数中获取文件指针
arg:参数
return:获取的文件指针
*/
static FILE *getArgsFilep(const char *arg) {
  FILE *fp = fopen(arg, "rb");
  if (fp == NULL)
    printf("File not found.\n");
  return fp;
}
/*
getArgsKey:从参数中获取密钥
arg:参数
return:获取的密钥
*/
static u8_t *getArgsKey(const char *arg) {
  u8_t *keyout = new u8_t[16];
  base64_to_hex((const u8_t *)arg, 24, keyout);
  return keyout;
}
/*
getRandomBuffer:获取随机的缓冲数组
r_buf:缓冲数组地址
*/
static void getRandomBuffer(u8_t *r_buf) {
  u8_t len = rand();
  for (int i = 0; i < len; ++i)
    r_buf[i] = rand();
}
/*
接口函数
get_v_mod2:根据输入的变量获得参数包
argc:变量数目
argv:变量值列表
return:返回的参数包
*/
unsigned char *get_v_mod2(int argc, char *argv[]) {
  char outn[138];
  srand(time(NULL));
  vpak_t *res = new vpak_t;
  res->mode = argv[1][1];
  if (strcmp(argv[1], "-e") == 0) {
    res->fp = getArgsFilep(argv[2]);
    if (strcmp(argv[3], "G") == 0)
      res->key = getRandomKey();
    else
      res->key = getArgsKey(argv[3]);
    sprintf(outn, "%s.wenc", argc == 4 ? argv[2] : argv[4]);
    res->out = fopen(outn, "wb+");
    getRandomBuffer(res->r_buf);
  } else if (strcmp(argv[1], "-d") == 0) {
    res->fp = getArgsFilep(argv[2]);
    res->key = getArgsKey(argv[3]);
    if (argc == 4) {
      sprintf(outn, "%s.denc", argv[2]);
      res->out = fopen((const char *)outn, "wb+");
    } else
      res->out = fopen(argv[4], "wb+");
  } else if (strcmp(argv[1], "-v") == 0) {
    res->out = NULL;
    res->fp = getArgsFilep(argv[2]);
    res->key = getArgsKey(argv[3]);
  } else
    res->fp = NULL;
  printkey(res->key);
  return (u8_t *)res;
}