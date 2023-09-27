#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/cry.h"
#include "../include/getval.h"
#include "../include/util.h"

struct vpak get_v_mod1() {
  struct vpak res;
  int r;
  printf("Need encrypt or decrypt?(e/d) ");
  r = scanf("%c", &res.mode);
  printf("File name:\n");
  char fn[128], outn[138], kn[128];
  while (1) {
    r = scanf("%s", fn);
    res.fp = fopen(fn, "rb");
    if(res.fp != NULL)break;
    printf("File not found.\n");
  }
  if (res.mode == 'e' || res.mode == 'E') {
    printf("Need generate a new key?(y/n) ");
    char flag;
    r = scanf("%*[\n]%c", &flag);
    if (flag == 'y' || flag == 'Y') {
      res.key = gen_key();
    } else {
      printf("Enter 128 bits (16 bytes) key in base64 mod:\n");
      r = scanf("%s", kn);
      res.key = malloc(16 * sizeof(unsigned char));
      base64_to_hex(kn, strlen(kn), res.key);
    }
    sprintf(outn, "%s.wenc", fn);
    res.out = fopen(outn, "wb+");
  } else {
    char decn[128];
    printf("Need a new name for decrypted file?(y/n) ");
    char flag;
    r = scanf("%*[\n]%c", &flag);
    if (flag == 'y' || flag == 'Y') {
      printf("Enter new name:\n");
      r = scanf("%s", decn);
      res.out = fopen(decn, "wb+");
    } else {
      sprintf(outn, "%s.wdec", fn);
      res.out = fopen(outn, "wb+");
    }
    printf("Enter 128 bits (16 bytes) key in base64 mod:\n");
    r = scanf("%s", kn);
    res.key = malloc(16 * sizeof(unsigned char));
    base64_to_hex(kn, strlen(kn), res.key);
  }
  return res;
}

struct vpak get_v_mod2(int argc, char *argv[]) {
  struct vpak res;
  res.mode = argv[1][1];
  if (strcmp(argv[1], "-e") == 0) {
    res.fp = fopen(argv[2], "rb");
    if (res.fp == NULL) {
      printf("File not found.\n");
      return res;
    }
    if (strcmp(argv[3], "G") == 0) {
      res.key = gen_key();
    } else {
      res.key = malloc(16 * sizeof(unsigned char));
      base64_to_hex(argv[3], strlen(argv[3]), res.key);
    }
    unsigned char outn[138];
    if (argc == 4) {
      sprintf(outn, "%s.wenc", argv[2]);
    } else {
      sprintf(outn, "%s.wenc", argv[4]);
    }
    res.out = fopen(outn, "wb+");
  } else {
    res.fp = fopen(argv[2], "rb");
    if (res.fp == NULL) {
      printf("File not found.\n");
      return res;
    }
    res.key = malloc(16 * sizeof(unsigned char));
    base64_to_hex(argv[3], strlen(argv[3]), res.key);
    if (argc == 4) {
      unsigned char outn[138];
      sprintf(outn, "%s.denc", argv[2]);
      res.out = fopen(outn, "wb+");
    } else {
      res.out = fopen(argv[4], "wb+");
    }
  }
  return res;
}
