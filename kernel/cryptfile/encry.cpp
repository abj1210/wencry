#include "cry.h"
#include <string.h>
/*
getFileHeader:构造加密文件头
r_buf:随机缓冲数组
*/
void runcrypt::getFileHeader(const u8_t *r_buf) {
  u8_t padding[21];
  padding[20] = 0;
  u64_t mn = Magic_Num;
  fwrite(&mn, 1, 7, out);
  sha1Stringhash(key, 16).getres(hash);
  fwrite(hash, 1, 20, out);
  fwrite(padding, 1, 21, out);
  sha1Stringhash(r_buf, strlen((const char *)r_buf)).getres(hash);
  fwrite(hash, 1, 20, out);
}
/*
hashfile:对加密后的文件进行哈希并写入输出文件
*/
void runcrypt::hashfile() {
  fseek(out, 47, SEEK_SET);
  fwrite(&tail, 1, 1, out);
  fseek(out, 48, SEEK_SET);
  sha1Filehash(out).getres(hash);
  fseek(out, 27, SEEK_SET);
  fwrite(hash, 1, 20, out);
}
/*
接口函数
enc:将文件加密
r_buf:随机缓冲数组
*/
void runcrypt::enc(const u8_t *r_buf) {
  getFileHeader(r_buf);
  multienc_master(fp, out, key, hash, tail);
  hashfile();
}
