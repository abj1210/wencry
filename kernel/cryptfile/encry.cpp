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
  fwrite(&mn, 1, 8, out);
  fwrite(padding, 1, 20, out);
  sha1Stringhash(r_buf, strlen((const char *)r_buf)).getres(iv);
  fwrite(iv, 1, 20, out);
  for (int i = 1; i < multicry_master::THREADS_NUM; ++i) {
    sha1Stringhash(iv + (20 * (i - 1)), strlen((const char *)r_buf))
        .getres(iv + (20 * i));
    fwrite(iv + (20 * i), 1, 20, out);
  }
}
/*
hashfile:计算文件的HMAC
*/
void runcrypt::hashfile() {
  fseek(out, 28, SEEK_SET);
  hmachandle.gethmac(key, out, hash);
  fseek(out, 8, SEEK_SET);
  fwrite(hash, 1, 20, out);
}
/*
接口函数
enc:将文件加密
r_buf:随机缓冲数组
ctype:加密模式
*/
void runcrypt::enc(const u8_t *r_buf, u8_t ctype) {
  getFileHeader(r_buf);
  multienc_master cm(fp, out, key, iv, ctype);
  cm.run_multicry();
  hashfile();
}
