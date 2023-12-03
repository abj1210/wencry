#include "key.h"
#include "wenctrl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
/*
getArgsFilep:从参数中获取文件指针
return:获取的文件指针
*/
static FILE *getArgsFilep(const char *arg) {
  FILE *fp = fopen(arg, "rb");
  if (fp == NULL)
    printf("File not found.\n");
  return fp;
}
/*
getInputFilep:从输入中获取文件指针
return:获取的文件指针
*/
static FILE *getInputFilep() {
  char fn[128];
  FILE *fp;
  while (1) {
    int r = scanf("%s", fn);
    fp = fopen(fn, "rb");
    if (fp != NULL)
      break;
    printf("File not found.\n");
  }
  return fp;
}
/*
getInputFilep:从输入中获取密钥
return:获取的密钥序列
*/
static keyhandle *getInputKey() {
  u8_t kn[128] = "";
  printf("Enter 128 bits (16 bytes) key in base64 mod:\n");
  int r = scanf("%*[\n]");
  while (scanf("%s", kn) == 0) {
    r = scanf("%*[\n]");
    printf("Sorry, please enter 128 bits (16 bytes) key in base64 mod:\n");
  }
  return new keyhandle(kn);
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
get_v_mod1:根据用户输入获得参数包
return:返回的参数包
*/
vpak_t get_v_mod1() {
  char flag, fn[] = "out", outn[138], decn[128], outk[128];
  srand(time(NULL));
  vpak_t res;
  printf("Need encrypt, verify or decrypt?(e/v/d) ");
  int r = scanf("%c", &res.mode);
  printf("File name:\n");
  res.fp = getInputFilep();
  if (res.mode == 'e' || res.mode == 'E') {
    printf("Need generate a new key?(y/n) ");
    r = scanf("%*[\n]%c", &flag);
    if (flag == 'y' || flag == 'Y')
      res.key = new keyhandle();
    else
      res.key = getInputKey();
    sprintf(outn, "%s.wenc", fn);
    res.out = fopen(outn, "wb+");
    res.key->get_initkey((u8_t *)outk);
    printf("Key is:\n %s\n", outk);
    printf("Please input some random characters.\n");
    r = scanf("%s", res.r_buf);
  } else if (res.mode == 'd' || res.mode == 'D') {
    printf("Need a new name for decrypted file?(y/n) ");
    r = scanf("%*[\n]%c", &flag);
    if (flag == 'y' || flag == 'Y') {
      printf("Enter new name:\n");
      r = scanf("%*[\n]");
      r = scanf("%s", decn);
      res.out = fopen(decn, "wb+");
    } else {
      sprintf(outn, "%s.wdec", fn);
      res.out = fopen(outn, "wb+");
    }
    res.key = getInputKey();
  } else if (res.mode == 'v') {
    res.key = getInputKey();
    res.out = NULL;
  } else
    res.fp = NULL;
  return res;
}
/*
接口函数
get_v_mod2:根据输入的变量获得参数包
argc:变量数目
argv:变量值列表
return:返回的参数包
*/
vpak_t get_v_mod2(int argc, char *argv[]) {
  char outn[138], outk[128];
  srand(time(NULL));
  vpak_t res;
  res.mode = argv[1][1];
  if (strcmp(argv[1], "-e") == 0) {
    res.fp = getArgsFilep(argv[2]);
    if (strcmp(argv[3], "G") == 0)
      res.key = new keyhandle();
    else
      res.key = new keyhandle((u8_t *)argv[3]);
    sprintf(outn, "%s.wenc", argc == 4 ? argv[2] : argv[4]);
    res.out = fopen(outn, "wb+");
    getRandomBuffer(res.r_buf);
  } else if (strcmp(argv[1], "-d") == 0) {
    res.fp = getArgsFilep(argv[2]);
    res.key = new keyhandle((u8_t *)argv[3]);
    if (argc == 4) {
      sprintf(outn, "%s.denc", argv[2]);
      res.out = fopen((const char *)outn, "wb+");
    } else
      res.out = fopen(argv[4], "wb+");
  } else if (strcmp(argv[1], "-v") == 0) {
    res.out = NULL;
    res.fp = getArgsFilep(argv[2]);
    res.key = new keyhandle((u8_t *)argv[3]);
  } else
    res.fp = NULL;
  res.key->get_initkey((u8_t *)outk);
  printf("Key is:\n %s\n", outk);
  return res;
}
