#include "cry.h"
#include <string.h>
/*
getFileHeader:构造加密文件头
out:输出的加密文件
key:初始密钥
r_buf:随机缓冲数组
r_hash:随机缓冲哈希
*/
static void getFileHeader(FILE *out, const u8_t *key, const u8_t *r_buf,
                          u8_t *r_hash) {
  u8_t padding[21];
  padding[20] = 0;
  u64_t mn = Magic_Num;
  fwrite(&mn, 1, 7, out);
  sha1Stringhash(key, 16).getres(r_hash);
  fwrite(r_hash, 1, 20, out);
  fwrite(padding, 1, 21, out);
  sha1Stringhash(r_buf, strlen((const char *)r_buf)).getres(r_hash);
  fwrite(r_hash, 1, 20, out);
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
  sha1Filehash(out).getres(hash);
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
  u8_t r_hash[20];
  getFileHeader(out, key, r_buf, r_hash);
  u8_t tail = 16;
  multienc_master(fp, out, key, r_hash, tail);
  hashfile(out, tail);
}
