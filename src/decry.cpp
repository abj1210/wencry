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
    free(chash);
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

  unsigned char *chash = getsha1f(fp);
  if (cmphash(chash, hash) != 0) {
    free(chash);
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
void decrypt_file(int tail, FILE *fp, FILE *out) {
  fseek(fp, 41, SEEK_SET);
  struct buffer *input = &ibuf, *output = &obuf;
  int tsum = load_buffer(fp, input);
  printf("Buffer loaded %dMB:*", BUF_SZ >> 16);
  fflush(stdout);
  struct state block;
  int idx = 0;
  while (1) {
    char sum = wread_buffer(idx, block, input);
    if (sum == -1) {
      int tsum = load_buffer(fp, input);
      printf("*");
      fflush(stdout);
      if (tsum == 0) {
        final_write(out, output);
        fwrite(&block, 1, tail, out);
        break;
      }
      idx = 0;
      store_buffer(out, output);
      sum = wread_buffer(idx, block, input);
    }
    decaes_128bit(block);
    if (bufferover(input)) {
      final_write(out, output);
      fwrite(&block, 1, tail, out);
      break;
    } else
      wwrite_buffer(idx, block, output);
    idx++;
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
int dec(FILE *fp, FILE *out, unsigned char *key) {
  int tail = verify(fp, key);
  if (tail < 0)
    return -tail;
  initgen(key);
  printf("Begin to decrypt.\n");
  decrypt_file(tail, fp, out);
  printf("Decrypted.\n");
  printf("Execute over!\n");
  return 0;
}
