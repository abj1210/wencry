#include "cry.h"
#include "multicry.h"
#include "sha1.h"

#include <string.h>
/*
getFileHeader:构造加密文件头
out:输出的加密文件
key:初始密钥
r_buf:随机缓冲哈希
*/
void getFileHeader(FILE *out, u8_t *key, u8_t *r_buf) {
  u8_t padding[21], hash[20];
  padding[20] = 0;
  u64_t mn = Magic_Num;
  fwrite(&mn, 1, 7, out);
  getSha1String(key, 16, hash);
  fwrite(hash, 1, 20, out);
  fwrite(padding, 1, 21, out);
  fwrite(r_buf, 1, 20, out);
}
/*
hashfile:对加密后的文件进行哈希并写入输出文件
out:加密后的文件
*/
void hashfile(FILE *out, u8_t tail) {
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
void enc(FILE *fp, FILE *out, u8_t *r_buf, keyhandle *key) {
  u8_t r_hash[20];
  getSha1String(r_buf, strlen((const char *)r_buf), r_hash);
  getFileHeader(out, key->get_initkey(), r_hash);
  buffergroup *buf = new buffergroup(THREADS_NUM, fp, out, r_hash);
  u8_t tail = 0;
  multienc_master(key, buf, tail);
  hashfile(out, tail);
  delete buf;
}
