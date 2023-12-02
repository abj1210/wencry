#include "cry.h"
#include "multicry.h"
#include "sha1.h"
/*
getFileHeader:构造加密文件头
out:输出的加密文件
key:初始密钥
*/
void getFileHeader(FILE *out, u8_t *key) {
  u8_t padding[21], hash[20];
  padding[20] = 0;
  u64_t mn = Magic_Num;
  fwrite(&mn, 1, 7, out);
  getSha1String(key, 16, hash);
  fwrite(hash, 1, 20, out);
  fwrite(padding, 1, 21, out);
}
/*
hashfile:对加密后的文件进行哈希并写入输出文件
out:加密后的文件
*/
void hashfile(FILE *out) {
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
key:密钥
*/
void enc(FILE *fp, FILE *out, keyhandle *key) {
  getFileHeader(out, key->get_initkey());
  multienc_master(fp, out, key, THREADS_NUM);
  hashfile(out);
}
