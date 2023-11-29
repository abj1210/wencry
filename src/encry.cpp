#include "aes.h"
#include "cry.h"
#include "key.h"
#include "multicry.h"
#include "sha1.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>

extern struct iobuffer buf;

/*
getFileHeader:构造加密文件头
out:输出的加密文件
key:初始密钥
*/
void getFileHeader(FILE *out, unsigned char *key) {
  unsigned char mn[8], padding[21];
  *(unsigned long long *)mn = Magic_Num;
  fwrite(mn, 1, 7, out);
  unsigned char *hash = getSha1String(key, 16);
  fwrite(hash, 1, 20, out);
  fwrite(padding, 1, 21, out);
  delete[] hash;
}
/*
encrypt_file:从输入缓冲区获取文件数据进行加密并写入输出缓冲区
fp:输入文件
out:输出文件
*/
void encrypt_file(FILE *fp, FILE *out, struct iobuffer &buf) {
  load_files(&buf, fp, out);
  printf("Buffer loaded %dMB:*", BUF_SZ >> 16);
  fflush(stdout);

  while (1) {
    struct state *block = (struct state *)get_entry(&buf);
    if (block == NULL) {
      if (buffer_over(&buf)) {
        char sum = final_write(&buf, 16);
        fseek(out, 47, SEEK_SET);
        fwrite(&sum, 1, 1, out);
        break;
      } else {
        printf("*");
        fflush(stdout);
        update_buffer(&buf);
      }
    } else
      runaes_128bit(*block);
  }
  printf("\n");
}
/*
hashfile:对加密后的文件进行哈希并写入输出文件
out:加密后的文件
*/
void hashfile(FILE *out) {
  fseek(out, 48, SEEK_SET);
  unsigned char *hash = getSha1File(out);
  fseek(out, 27, SEEK_SET);
  fwrite(hash, 1, 20, out);
  delete[] hash;
}
/*
接口函数
enc:将文件加密
fp:输入文件
out:加密后文件
key:初始密钥序列
*/
void enc(FILE *fp, FILE *out, unsigned char *key) {
  //初始化
  getFileHeader(out, key);
  initgen(key);
  //加密
#ifndef MULTI_ENABLE
  encrypt_file(fp, out, buf);
#else
  multienc_master(fp, out, THREADS_NUM);
#endif
  //获取哈希
  hashfile(out);
  return;
}
