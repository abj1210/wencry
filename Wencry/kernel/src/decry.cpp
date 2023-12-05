#include "cry.h"
#include "multicry.h"
#include "sha1.h"
/*
cmphash:比较哈希值
h1:待比较的哈希数组
h2:待比较的哈希数组
return:哈希是否相同
*/
static bool cmphash(const u8_t *h1, const u8_t *h2) {
  for (int i = 0; i < 20; ++i)
    if (h1[i] != h2[i])
      return false;
  return true;
}
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
  u8_t hash[20], chash[20];
  int sum = fread(hash, 1, 20, fp);
  if (sum != 20)
    return -1;
  getSha1String(key, 16, chash);
  if (!cmphash(chash, hash))
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
  u8_t hash[20], chash[29];
  int sum = fread(hash, 1, 20, fp);
  if (sum != 20)
    return -1;
  u8_t tail;
  int rx = fread(&tail, 1, 1, fp);
  if (rx != 1)
    return -1;
  getSha1File(fp, chash);
  if (!cmphash(chash, hash))
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
get_RBH:获取随机缓冲哈希
fp:输入文件指针
return:返回的RBH,若失败返回NULL
*/
u8_t *get_BRH(FILE *fp) {
  u8_t *r_buf = new u8_t[20];
  if (fread(r_buf, 1, 20, fp) != 20) {
    delete r_buf;
    return NULL;
  }
  return r_buf;
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
  u8_t *r_buf = get_BRH(fp);
  if (r_buf == NULL)
    return -1;
  buffergroup *buf = new buffergroup(THREADS_NUM, fp, out);
  multidec_master(key, buf, r_buf, tail);
  delete buf;
  delete r_buf;
  return 0;
}
