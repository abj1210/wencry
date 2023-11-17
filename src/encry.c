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
printOut:打印处理进度
bnum:以处理的数据size(以MB计数)
return:bnum+1
*/
int printOut(int bnum) {
  bnum++;
  printf("\b\b\b\b\b\b\b\b\b");
  printf("%05d MB.", bnum);
  fflush(stdout);
  return bnum;
}
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
encrypt_128bit:从输入缓冲区获取128bit数据进行加密并写入输出缓冲区
idx:待从输入缓冲区获取的16B单元索引
fp:输入文件
out:输出文件
return:下一次加密时的索引,若为-1则代表加密结束
*/
int encrypt_128bit(int idx, FILE *fp, FILE *out) {
  unsigned char block[16];
  char sum = wread_buffer(idx, block, &ibuf);
  if (sum == -1) {
    int tsum = load_buffer(fp, &ibuf);
    if (tsum == 0) {
      final_write(out, &obuf);
      fseek(out, 40, SEEK_SET);
      fwrite(&sum, 1, 1, out);
      return -1;
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
    return -1;
  }
  return idx;
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
  unsigned short round = 0;
  unsigned int bnum = 0;
  int idx = 0;

  getFileHeader(out, key);
  initgen(key);

#ifdef MULTI_ENABLE
  int tsum = load_buffer(fp, &ibuf);
#else
  int tsum = load_buffer(fp, &ibuf);
#endif

  printf("Begin to encrypt.\n");
  printf("Encrypted: 00000000 MB.");
  fflush(stdout);
  while (1) {
    round++;
    if (round == 0)
      bnum = printOut(bnum);
    idx = encrypt_128bit(idx, fp, out);
    if (idx == -1)
      break;
  }

  printf("\n Encrypted.\n");
  printf("Begin to hash.\n");
  hashfile(out);
  printf("Execute over!\n");
  return;
}
