#include "aes.h"
#include "cry.h"
#include "key.h"
#include "sha1.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

extern struct buffer ibuf, obuf;
/*
getFileHeader:构造加密文件头
out:输出的加密文件
key:初始密钥
*/
void getFileHeader(FILE *out, unsigned char *key) {
  unsigned char *hash = getsha1s(key, 16);
  fwrite(hash, 1, 20, out);
  fwrite(hash, 1, 20, out);
  free(hash);
  unsigned char z = 0;
  fwrite(&z, 1, 1, out);
}
/*
encrypt_file:从输入缓冲区获取文件数据进行加密并写入输出缓冲区
fp:输入文件
out:输出文件
*/
void encrypt_file(FILE *fp, FILE *out) {
  struct buffer *input = &ibuf, *output = &obuf;
  int tsum = load_buffer(fp, input);
  printf("Buffer loaded %dMB:*", BUF_SZ >> 16);
  fflush(stdout);
  unsigned char block[16];
  int idx = 0;
  while (1) {
    char sum = wread_buffer(idx, block, input);
    if (sum == -1) {
      tsum = load_buffer(fp, input);
      printf("*");
      fflush(stdout);
      if (tsum == 0) {
        final_write(out, output);
        fseek(out, 40, SEEK_SET);
        fwrite(&sum, 1, 1, out);
        break;
      }
      idx = 0;
      store_buffer(out, output);
      sum = wread_buffer(idx, block, input);
    }
    runaes_128bit(block);
    wwrite_buffer(idx, block, output);
    idx++;
    if (sum != 16) {
      final_write(out, output);
      fseek(out, 40, SEEK_SET);
      fwrite(&sum, 1, 1, out);
      break;
    }
  }
  printf("\n");
}
/*
hashfile:对加密后的文件进行哈希并写入输出文件
out:加密后的文件
*/
void hashfile(FILE *out) {
  fseek(out, 41, SEEK_SET);
  unsigned char *hash = getsha1f(out);
  fseek(out, 20, SEEK_SET);
  fwrite(hash, 1, 20, out);
  free(hash);
}
/*
接口函数
enc:将文件加密
fp:输入文件
out:加密后文件
key:初始密钥序列
*/
void enc(FILE *fp, FILE *out, unsigned char *key) {
  getFileHeader(out, key);
  initgen(key);
  printf("Begin to encrypt.\n");
  encrypt_file(fp, out);
  printf("Encrypted.\n");
  printf("Begin to hash.\n");
  hashfile(out);
  printf("Execute over!\n");
  return;
}
