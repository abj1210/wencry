#include "sha1.h"
#include <string.h>
/*
getwdata:根据每个输入单元生成sha1中w数组的值
s:输入的单元
w:生成的w数组
return:w的地址
*/
static void getwdata(const u8_t *s, wdata_t &w) {
  u32_t t, i = 0;
  for (i; i < 16; ++i) {
    t = *((u32_t *)s + i);
    setbytes(w.w[i], ((u8_t)(t >> 24)), ((u8_t)(t >> 16)), ((u8_t)(t >> 8)), t);
  }
  for (i; i < 80; ++i) {
    t = (w.w[i - 3]) ^ (w.w[i - 8]) ^ (w.w[i - 14]) ^ (w.w[i - 16]);
    w.w[i] = lrot(t, 1);
  }
}
/*
gethash:获取每一步的哈希值
h:上一步的哈希值
w:生成的w数组
*/
static void gethash(hash_t &h, const wdata_t &w) {
  u32_t temph0 = h.h[0], temph1 = h.h[1], temph2 = h.h[2], temph3 = h.h[3],
        temph4 = h.h[4];
  u32_t f, temp;
  for (u32_t i = 0; i < 80; ++i) {
    if (i < 20) {
      f = (temph1 & temph2) | ((~temph1) & temph3);
      temp = lrot(temph0, 5) + f + 0x5A827999 + temph4 + w.w[i];
    } else if (i < 40) {
      f = temph1 ^ temph2 ^ temph3;
      temp = lrot(temph0, 5) + f + 0x6ED9EBA1 + temph4 + w.w[i];
    } else if (i < 60) {
      f = (temph1 & temph2) | (temph1 & temph3) | (temph2 & temph3);
      temp = lrot(temph0, 5) + f + 0x8F1BBCDC + temph4 + w.w[i];
    } else {
      f = temph1 ^ temph2 ^ temph3;
      temp = lrot(temph0, 5) + f + 0xCA62C1D6 + temph4 + w.w[i];
    }
    temph4 = temph3;
    temph3 = temph2;
    temph2 = lrot(temph1, 30);
    temph1 = temph0;
    temph0 = temp;
  }
  h.h[0] += temph0;
  h.h[1] += temph1;
  h.h[2] += temph2;
  h.h[3] += temph3;
  h.h[4] += temph4;
}
/*
接口函数
getSha1File:获取文件的sha1哈希值
fp:输入文件
return:生成的sha1哈希序列
*/
void getSha1File(FILE *fp, u8_t *hashout) {
  buffer64 *ibuf64 = new buffer64(fp);
  hash_t h;
  u8_t s1[64];
  int flag = 0;
  wdata_t w;
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
    getwdata(s1, w);
    gethash(h, w);
  }
  for (int i = 0; i < 20; ++i)
    hashout[i] = (u8_t)((h.h[i >> 2]) >> ((3 - (i & 0x3)) << 3));
  delete ibuf64;
}
/*
接口函数
getSha1String:获取字符串的sha1哈希值
s:输入字符串
n:字符串长度
return:生成的sha1哈希序列
*/
void getSha1String(const u8_t *s, u32_t n, u8_t *hashout) {
  hash_t h;
  u64_t b = n * 8, cnum;
  int flag = 0;
  if ((b + 8) % 512 >= 448)
    cnum = b / 512 + 2;
  else
    cnum = b / 512 + 1;
  u8_t s1[64];
  wdata_t w;
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
    getwdata(s1, w);
    gethash(h, w);
  }
  for (int i = 0; i < 20; ++i)
    hashout[i] = (u8_t)((h.h[i >> 2]) >> ((3 - (i & 0x3)) << 3));
}