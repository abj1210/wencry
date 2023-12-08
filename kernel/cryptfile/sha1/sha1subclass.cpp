#include "sha1.h"
#include "macro.h"
#include <string.h>
/*
构造函数:获取文件的sha1哈希值
fp:输入文件
*/
sha1Filehash::sha1Filehash(FILE *fp):
  sha1hash(), ibuf64(new buffer64(fp)) {
  u8_t s1[64];
  int flag = 0;
  for (u32_t i = 0; flag != 2; ++i) {
    memset(s1, 0, sizeof(s1));
    u32_t sum = ibuf64->read_buffer64(s1);
    if (sum != 64 && flag == 0) {
      s1[sum++] = 0x80u;
      flag = 1;
    }
    if (sum < 56) {
      u64_t b = (u64_t)i * 512 + (sum - 1) * 8;
      for (int i = 0; i < 8; ++i)
        s1[56 + i] = (u8_t)((b >> ((7 - i) << 3)));
      flag = 2;
    }
    getwdata(s1);
    gethash();
  }
}
/*
构造函数:获取字符串的sha1哈希值
s:输入字符串
n:字符串长度
*/
sha1Stringhash::sha1Stringhash(const u8_t *s,const u32_t n) {
  u64_t b = n * 8, cnum;
  int flag = 0;
  if ((b + 8) % 512 >= 448)
    cnum = b / 512 + 2;
  else
    cnum = b / 512 + 1;
  u8_t s1[64];
  for (u32_t i = 0; i < cnum; ++i) {
    memset(s1, 0, sizeof(s1));
    if ((i << 6) < n) {
      if (n - (i << 6) < 64) {
        memcpy(s1, s + (i << 6), n - (i << 6));
        s1[n - (i << 6)] = 0x80u;
        flag = 1;
      } else
        memcpy(s1, s + (i << 6), 64);
    } else if (!flag)
      s1[0] = 0x80u;
    if (i == cnum - 1)
      for (int i = 0; i < 8; ++i)
        s1[56 + i] = (u8_t)((b >> ((7 - i) << 3)));
    getwdata(s1);
    gethash();
  }
}