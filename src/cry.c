
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../include/aes.h"
#include "../include/cry.h"
#include "../include/key.h"
#include "../include/sha1.h"
#include "../include/util.h"

struct buffer ibuf, obuf;
/*
接口函数
init:初始化设置
*/
void init() {
  srand(time(NULL));
  obuf.total = 0;
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
checkKey:检查密钥是否一致
fp:输入文件
key:输入的密钥序列
return:若为0则检查通过,否则检查不通过
*/
int checkKey(FILE *fp, unsigned char *key) {
  unsigned char hash[20];
  int sum = fread(hash, 1, 20, fp);
  if (sum != 20)
    return -1;
  unsigned char *chash = getsha1s(key, 16);
  if (cmphash(chash, hash) != 0) {
    free(chash);
    return -2;
  }
  free(chash);
  return 0;
}
/*
checkFile:检查文件是否被篡改
fp:输入文件
return:若为非负数则检查通过,返回值为原文件大小与16的模,否则检查不通过
*/
int checkFile(FILE *fp) {
  unsigned char hash[20];
  int sum = fread(hash, 1, 20, fp);
  if (sum != 20)
    return -1;

  unsigned char tail;
  int rx = fread(&tail, 1, 1, fp);

  unsigned char *chash = getsha1f(fp);
  if (cmphash(chash, hash) != 0) {
    free(chash);
    return -3;
  }

  free(chash);
  return tail;
}
/*
decrypt_128bit:从输入缓冲区获取128bit数据进行解密并写入输出缓冲区
idx:待从输入缓冲区获取的16B单元索引
tail:原文件大小与16的模
fp:输入文件
out:输出文件
return:下一次加密时的索引,若为-1则代表加密结束
*/
int decrypt_128bit(int idx, int tail, FILE *fp, FILE *out) {
  unsigned char block[16];
  char sum = wread_buffer(idx, block, &ibuf);
  if (sum == -1) {
    int tsum = load_buffer(fp, &ibuf);
    if (tsum == 0) {
      final_write(out, &obuf);
      fwrite(block, 1, tail, out);
      return -1;
    }
    idx = 0;
    store_buffer(out, &obuf);
    sum = wread_buffer(idx, block, &ibuf);
  }
  decaes_128bit(block);
  if (bufferover(&ibuf)) {
    final_write(out, &obuf);
    fwrite(block, 1, tail, out);
    return -1;
  } else
    wwrite_buffer(idx, block, &obuf);
  idx++;
  return idx;
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
/*
接口函数
dec:将文件解密
fp:输入文件
out:解密后文件
key:初始密钥序列
return:若成功解密则返回0,否则返回非零值
*/
int dec(FILE *fp, FILE *out, unsigned char *key) {
  unsigned short round = 0;
  unsigned int bnum = 0;
  int tail = 0;
  printf("Begin to check.\n");
  int res = checkKey(fp, key);
  if (res < 0)
    return -res;
  printf("Key check OK.\n");
  res = checkFile(fp);
  if (res < 0)
    return -res;
  else
    tail = res;
  printf("File check OK.\n");

  fseek(fp, 41, SEEK_SET);
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
    if (round == 0)
      bnum = printOut(bnum);
    idx = decrypt_128bit(idx, tail, fp, out);
    if (idx == -1)
      break;
  }
  printf("\n Decrypted.\n");

  printf("Execute over!\n");
  return 0;
}