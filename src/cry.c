#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "../include/aes.h"
#include "../include/cry.h"
#include "../include/sha1.h"
#include "../include/util.h"

struct buffer ibuf, obuf;
/*
init:初始化设置
*/
void init() {
  srand(time(NULL));
  obuf.total = 0;
}
/*
gen_key:随机产生一初始密钥
return:产生的初始密钥
*/
unsigned char *gen_key() {
  unsigned char *key = (unsigned char *)malloc(16 * sizeof(unsigned char));
  for (int i = 0; i < 16; i++) {
    key[i] = rand() & 0xff;
  }
  return key;
}
/*
cmphash:比较哈希值
h1:待比较的哈希数组
h2:待比较的哈希数组
return:若相同返回0,否则返回1
*/
int cmphash(unsigned char *h1, unsigned char *h2) {
  for (int i = 0; i < 20; i++) {
    if (h1[i] != h2[i])
      return 1;
  }
  return 0;
}
/*
enc:将文件加密
fp:输入文件
out:加密后文件
key:初始密钥序列
*/
void enc(FILE *fp, FILE *out, unsigned char *key) {
  unsigned short round = 0;
  unsigned int bnum = 0;
  unsigned char *hash = getsha1s(key, 16);
  fwrite(hash, 1, 20, out);
  fwrite(hash, 1, 20, out);
  free(hash);
  unsigned char z = 0;
  fwrite(&z, 1, 1, out);

  initgen(key);
  unsigned char block[16];
#ifdef MULTI_ENABLE
  int tsum = load_buffer(fp, &ibuf);
#else
  int tsum = load_buffer(fp, &ibuf);
#endif
  printf("Begin to encrypt.\n");
  printf("Encrypted: 00000000 MB.");
  fflush(stdout);
  int idx = 0;
  while (1) {
    round++;
    if (round == 0) {
      bnum++;
      printf("\b\b\b\b\b\b\b\b\b");
      printf("%05d MB.", bnum);
      fflush(stdout);
    }
    char sum = wread_buffer(idx, block, &ibuf);
    if (sum == -1) {
      tsum = load_buffer(fp, &ibuf);
      if (tsum == 0) {
        final_write(out, &obuf);
        fseek(out, 40, SEEK_SET);
        fwrite(&sum, 1, 1, out);
        break;
      }
      idx = 0;
      store_buffer(out, &obuf);
      sum = wread_buffer(idx, block, &ibuf);
    }
    runaes_128bit(block);
    wwrite_buffer(idx, block, &obuf);
    idx++;
    if (sum != 16) {
      final_write(out, &obuf);
      fseek(out, 40, SEEK_SET);
      fwrite(&sum, 1, 1, out);
      break;
    }
  }
  printf("\n Encrypted.\n");
  printf("Begin to hash.\n");
  fseek(out, 41, SEEK_SET);
  hash = getsha1f(out);
  fseek(out, 20, SEEK_SET);
  fwrite(hash, 1, 20, out);
  free(hash);
  printf("Execute over!\n");
  return;
}
/*
enc:将文件解密
fp:输入文件
out:解密后文件
key:初始密钥序列
*/
int dec(FILE *fp, FILE *out, unsigned char *key) {
  printf("Begin to check.\n");
  unsigned char hash[20];
  int sum = fread(hash, 1, 20, fp);
  if (sum != 20)
    return 1;
  unsigned char *chash = getsha1s(key, 16);
  if (cmphash(chash, hash) != 0) {
    free(chash);
    return 2;
  }
  free(chash);
  printf("Key check OK.\n");

  sum = fread(hash, 1, 20, fp);
  if (sum != 20)
    return 1;

  unsigned char tail;
  unsigned short round = 0;
  unsigned int bnum = 0;
  int rx = fread(&tail, 1, 1, fp);

  chash = getsha1f(fp);
  if (cmphash(chash, hash) != 0) {
    free(chash);
    return 3;
  }

  free(chash);
  printf("File check OK.\n");

  fseek(fp, 41, SEEK_SET);
  unsigned char block[16];
  initgen(key);
  printf("Begin to decrypt.\n");
  printf("Decrypted: 00000000 MB.");
  fflush(stdout);
#ifdef MULTI_ENABLE
  int tsum = load_buffer(fp, &ibuf);
#else
  int tsum = load_buffer(fp, &ibuf);
#endif
  int idx = 0;
  while (1) {
    round++;
    if (round == 0) {
      bnum++;
      printf("\b\b\b\b\b\b\b\b\b");
      printf("%05d MB.", bnum);
      fflush(stdout);
    }
    char sum = wread_buffer(idx, block, &ibuf);
    if (sum == -1) {
      tsum = load_buffer(fp, &ibuf);
      if (tsum == 0) {
        final_write(out, &obuf);
        fwrite(block, 1, tail, out);
        break;
      }
      idx = 0;
      store_buffer(out, &obuf);
      sum = wread_buffer(idx, block, &ibuf);
    }
    decaes_128bit(block);
    if (bufferover(&ibuf)) {
      final_write(out, &obuf);
      fwrite(block, 1, tail, out);
      break;
    } else
      wwrite_buffer(idx, block, &obuf);
    idx++;
  }
  printf("\n Decrypted.\n");

  printf("Execute over!\n");
  return 0;
}