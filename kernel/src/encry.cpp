#include "cry.h"
#include "multicry.h"
#include "sha1.h"

#include <string.h>
/*
getFileHeader:构造加密文件头
out:输出的加密文件
key:初始密钥
r_buf:随机缓冲数组
return:随机缓冲哈希
*/
static u8_t *getFileHeader(FILE *out, const u8_t *key, const u8_t *r_buf) {
  u8_t padding[21];
  u8_t *hash = new u8_t[20];
  padding[20] = 0;
  u64_t mn = Magic_Num;
  fwrite(&mn, 1, 7, out);
  getSha1String(key, 16, hash);
  fwrite(hash, 1, 20, out);
  fwrite(padding, 1, 21, out);
  getSha1String(r_buf, strlen((const char *)r_buf), hash);
  fwrite(hash, 1, 20, out);
  return hash;
}
/*
hashfile:对加密后的文件进行哈希并写入输出文件
out:加密后的文件
tail:最后一表项装载的字节数
*/
static void hashfile(FILE *out, const u8_t tail) {
  fseek(out, 47, SEEK_SET);
  fwrite(&tail, 1, 1, out);
  fseek(out, 48, SEEK_SET);
  u8_t hash[20];
  getSha1File(out, hash);
  fseek(out, 27, SEEK_SET);
  fwrite(hash, 1, 20, out);
}
/*
接口函数
enc:将文件加密
fp:输入文件
out:加密后文件
r_buf:随机缓冲数组
key:密钥
*/
void enc(FILE *fp, FILE *out, const u8_t *r_buf, u8_t *key) {
  u8_t *r_hash = getFileHeader(out, key, r_buf);
  buffergroup *buf = new buffergroup(THREADS_NUM, fp, out);
  u8_t tail = 16;
  multienc_master(key, buf, r_hash, THREADS_NUM, tail);
  delete buf;
  delete r_hash;
  hashfile(out, tail);
}
