#include "sha1.h"
#include <string.h>
/*aEwkBVb3CeVNjg6yiDJjMw==
构造函数:获取文件的sha1哈希值
fp:输入文件
*/
sha1Filehash::sha1Filehash(FILE *fp) : sha1hash(), ibuf64(new buffer64(fp)) {
  u8_t s1[64];
  u64_t b = 0;
  while(true) {
    memset(s1, 0, sizeof(s1));
    u64_t sum = ibuf64->read_buffer64(s1);
    b += sum << 3;
    if (sum != 64) {
      s1[sum] = 0x80u;
      if (sum >= 56) {
        gethash(s1);
        memset(s1, 0, sizeof(s1));
      }
      for (int i = 0; i < 8; ++i)
        s1[56 + i] = (u8_t)((b >> ((7 - i) << 3)));
      gethash(s1);
      break;
    }
    gethash(s1);
  }
}
/*
构造函数:获取字符串的sha1哈希值
s:输入字符串
n:字符串长度
*/
sha1Stringhash::sha1Stringhash(const u8_t *s, const u32_t n) : sha1hash(){
  u32_t nnow;
  u64_t b = n << 3;
  u8_t s1[64];
  for (nnow = n; nnow >= 64; nnow -= 64) {
    memcpy(s1, s + (n - nnow), 64);
    gethash(s1);
  }
  memset(s1, 0, sizeof(s1));
  memcpy(s1, s + (n - nnow), nnow);
  s1[nnow] = 0x80u;
  if (nnow >= 56) {
    gethash(s1);
    memset(s1, 0, sizeof(s1));
  }
  for (int i = 0; i < 8; ++i)
    s1[56 + i] = (u8_t)((b >> ((7 - i) << 3)));
  gethash(s1);
}