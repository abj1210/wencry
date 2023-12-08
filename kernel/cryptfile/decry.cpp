#include "cry.h"
/*
checkMn:检查魔数
fp:输入文件
return:若为0则检查通过,否则检查不通过
*/
static int checkMn(FILE *fp) {
  u64_t mn = 0;
  int sum = fread(&mn, 1, 7, fp);
  if (sum != 7)
    return -1;
  return mn == Magic_Num ? 0 : -4;
}
/*
checkKey:检查密钥是否一致
fp:输入文件
key:输入的密钥序列
return:若为0则检查通过,否则检查不通过
*/
static int checkKey(FILE *fp, const u8_t *key) {
  u8_t hash[20];
  int sum = fread(hash, 1, 20, fp);
  if (sum != 20)
    return -1;
  sha1Stringhash hashhandle(key, 16);
  if (!hashhandle.cmphash(hash))
    return -2;
  else
    return 0;
}
/*
checkFile:检查文件是否被篡改
fp:输入文件
return:若为非负数则检查通过,返回值为原文件大小与16的模,否则检查不通过
*/
static int checkFile(FILE *fp) {
  u8_t hash[20];
  int sum = fread(hash, 1, 20, fp);
  if (sum != 20)
    return -1;
  u8_t tail;
  int rx = fread(&tail, 1, 1, fp);
  if (rx != 1)
    return -1;
  sha1Filehash hashhandle(fp);
  if (!hashhandle.cmphash(hash))
    return -3;
  fseek(fp, 48, SEEK_SET);
  return tail;
}
/*
接口函数
verify:验证密钥和文件
fp:输入文件
key:密钥
return:若为非负数则检查通过,返回值为原文件大小与16的模,否则检查不通过
*/
int verify(FILE *fp, u8_t *key) {
  int res = checkMn(fp);
  if (res < 0)
    return res;
  res = checkKey(fp, key);
  if (res < 0)
    return res;
  res = checkFile(fp);
  return res;
}
/*
接口函数
dec:将文件解密
fp:输入文件
out:解密后文件
key:密钥
return:若成功解密则返回0,否则返回非零值
*/
int dec(FILE *fp, FILE *out, u8_t *key) {
  u8_t tail = verify(fp, key);
  if (tail < 0)
    return -tail;
  u8_t r_buf[20];
  if (fread(r_buf, 1, 20, fp) != 20)
    return -1;
  multidec_master(fp, out, key, r_buf, tail);
  return 0;
}
