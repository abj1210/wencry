#include "aes.h"
#include "cry.h"
#include "key.h"
#include "multicry.h"
#include "sha1.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
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
    delete[] chash;
    return -2;
  }
  delete[] chash;
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
  if (rx != 1)
    return -1;

  unsigned char *chash = getsha1f(fp);
  if (cmphash(chash, hash) != 0) {
    delete[] chash;
    return -3;
  }

  delete[] chash;
  return tail;
}
/*
decrypt_file:从输入缓冲区获取文件数据进行解密并写入输出缓冲区
tail:原文件大小与16的模
fp:输入文件
out:输出文件
*/
void decrypt_file(int tail, FILE *fp, FILE *out, struct iobuffer &buf) {
  fseek(fp, 41, SEEK_SET);
  load_files(&buf, fp, out);
  printf("Buffer loaded %dMB:*", BUF_SZ >> 16);
  fflush(stdout);

  while (1) {
    struct state *block = (struct state *)get_entry(&buf);
    if (block == NULL) {
      if (buffer_over(&buf)) {
        final_write(&buf, tail);
        break;
      } else {
        update_buffer(&buf);
        printf("*");
        fflush(stdout);
      }
    } else
      decaes_128bit(*block);
  }
  printf("\n");
}
/*
接口函数
verify:验证密钥和文件
fp:输入文件
key:初始密钥序列
return:若为非负数则检查通过,返回值为原文件大小与16的模,否则检查不通过
*/
int verify(FILE *fp, unsigned char *key) {
  printf("Begin to check.\n");
  int res = checkKey(fp, key);
  if (res < 0) {
    printf("File check fail.\n");
    return res;
  } else
    printf("Key check OK.\n");
  res = checkFile(fp);
  if (res < 0)
    printf("File check fail.\n");
  else
    printf("File check OK.\n");
  return res;
}
/*
接口函数
dec:将文件解密
fp:输入文件
out:解密后文件
key:初始密钥序列
return:若成功解密则返回0,否则返回非零值
*/
int dec(FILE *fp, FILE *out, struct iobuffer &buf, unsigned char *key) {
  int tail = verify(fp, key);
  if (tail < 0)
    return -tail;
  initgen(key);
  printf("Begin to decrypt.\n");
#ifndef MULTI_ENABLE
  decrypt_file(tail, fp, out, buf);
#else
  multidec_master(fp, out, tail, THREADS_NUM);
#endif
  printf("Decrypted.\n");
  printf("Execute over!\n");
  return 0;
}
