#include "key.h"
#include "Autil.h"
#include "wenctrl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern void hex_to_base64(unsigned char *hex_in, int len,
                          unsigned char *base64_out);
extern void base64_to_hex(unsigned char *base64_in, int len,
                          unsigned char *hex_out);

/*
getInputFilep:从输入中获取文件指针
return:获取的文件指针
*/
FILE *getInputFilep() {
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
unsigned char *getInputKey() {
  char kn[128] = "";
  printf("Enter 128 bits (16 bytes) key in base64 mod:\n");
  int r = scanf("%*[\n]");
  while (scanf("%s", kn) == 0) {
    r = scanf("%*[\n]");
    printf("Sorry, please enter 128 bits (16 bytes) key in base64 mod:\n");
  }
  unsigned char *key = new unsigned char[16];
  base64_to_hex((unsigned char *)kn, strlen(kn), key);
  return key;
}
/*
接口函数
get_v_mod1:根据用户输入获得参数包
return:返回的参数包
*/
struct vpak get_v_mod1() {
  unsigned char outk[128];
  char flag, fn[] = "out", outn[138], decn[128];
  srand(time(NULL));
  struct vpak res;
  printf("Need encrypt, verify or decrypt?(e/v/d) ");
  int r = scanf("%c", &res.mode);
  printf("File name:\n");
  res.fp = getInputFilep();
  if (res.mode == 'e' || res.mode == 'E') {
    printf("Need generate a new key?(y/n) ");
    r = scanf("%*[\n]%c", &flag);
    if (flag == 'y' || flag == 'Y')
      res.key = gen_key();
    else
      res.key = getInputKey();
    sprintf(outn, "%s.wenc", fn);
    res.out = fopen(outn, "wb+");
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
  } else {
    res.fp = NULL;
    return res;
  }

  printf("Key is: \n");
  hex_to_base64(res.key, 16, outk);
  printf("%s\n", outk);
  return res;
}
/*
接口函数
get_v_mod2:根据输入的变量获得参数包
argc:变量数目
argv:变量值列表
return:返回的参数包
*/
struct vpak get_v_mod2(int argc, char *argv[]) {
  char outn[138];
  unsigned char outk[128];
  srand(time(NULL));
  struct vpak res;
  res.mode = argv[1][1];
  res.key = new unsigned char[16];
  if (strcmp(argv[1], "-e") == 0) {
    res.fp = fopen(argv[2], "rb");
    if (res.fp == NULL) {
      printf("File not found.\n");
      return res;
    }
    if (strcmp(argv[3], "G") == 0)
      res.key = gen_key();
    else
      base64_to_hex((unsigned char *)argv[3], strlen(argv[3]), res.key);
    if (argc == 4)
      sprintf(outn, "%s.wenc", argv[2]);
    else
      sprintf(outn, "%s.wenc", argv[4]);
    res.out = fopen(outn, "wb+");
  } else if (strcmp(argv[1], "-d") == 0) {
    res.fp = fopen(argv[2], "rb");
    if (res.fp == NULL) {
      printf("File not found.\n");
      return res;
    }
    base64_to_hex((unsigned char *)argv[3], strlen(argv[3]), res.key);
    if (argc == 4) {
      sprintf(outn, "%s.denc", argv[2]);
      res.out = fopen((const char *)outn, "wb+");
    } else
      res.out = fopen(argv[4], "wb+");
  } else if (strcmp(argv[1], "-v") == 0) {
    res.fp = fopen(argv[2], "rb");
    res.out = NULL;
    if (res.fp == NULL) {
      printf("File not found.\n");
      return res;
    }
    base64_to_hex((unsigned char *)argv[3], strlen(argv[3]), res.key);
  } else {
    res.fp = NULL;
    return res;
  }

  printf("Key is: \n");
  hex_to_base64(res.key, 16, outk);
  printf("%s\n", outk);
  return res;
}
