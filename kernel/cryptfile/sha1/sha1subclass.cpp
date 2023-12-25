#include "sha1.h"
#include <string.h>
/*
构造函数:获取文件的sha1哈希值
fp:输入文件
*/
sha1Filehash::sha1Filehash(FILE *fp) : sha1hash(), ibuf64(new buffer64(fp)) {
  while (true) {
    u64_t sum = ibuf64->read_buffer64(getLoadAddr());
    totalsize += sum << 3;
    if (sum != 64) {
      finalHash(sum);
      break;
    }
    gethash();
  }
}
/*
构造函数:获取拼接的sha1哈希值
block:拼接块
fp:输入文件
*/
sha1Filehash::sha1Filehash(u8_t * block, FILE *fp): sha1hash(), ibuf64(new buffer64(block, fp)){
  while (true) {
    u64_t sum = ibuf64->read_buffer64(getLoadAddr());
    totalsize += sum << 3;
    if (sum != 64) {
      finalHash(sum);
      break;
    }
    gethash();
  }
}
/*
构造函数:获取字符串的sha1哈希值
s:输入字符串
n:字符串长度
*/
sha1Stringhash::sha1Stringhash(const u8_t *s, const u32_t n) : sha1hash() {
  u32_t nnow;
  totalsize = n << 3;
  for (nnow = n; nnow >= 64; nnow -= 64) {
    memcpy(getLoadAddr(), s + (n - nnow), 64);
    gethash();
  }
  memcpy(getLoadAddr(), s + (n - nnow), nnow);
  finalHash(nnow);
}