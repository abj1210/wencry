#include "key.h"
#include "multicry.h"
#include "sha1.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>

/*
getFileHeader:构造加密文件头
out:输出的加密文件
key:初始密钥
*/
void getFileHeader(FILE *out, unsigned char *key) {
  unsigned char mn[8], padding[21];
  padding[20] = 0;
  *(unsigned long long *)mn = Magic_Num;
  fwrite(mn, 1, 7, out);
  unsigned char *hash = getSha1String(key, 16);
  fwrite(hash, 1, 20, out);
  fwrite(padding, 1, 21, out);
  delete[] hash;
}
/*
hashfile:对加密后的文件进行哈希并写入输出文件
out:加密后的文件
*/
void hashfile(FILE *out) {
  fseek(out, 48, SEEK_SET);
  unsigned char *hash = getSha1File(out);
  fseek(out, 27, SEEK_SET);
  fwrite(hash, 1, 20, out);
  delete[] hash;
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
