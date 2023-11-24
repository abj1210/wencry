#include "sha1.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct buffer64 ibuf64;
/*
getwdata:根据每个输入单元生成sha1中w数组的值
s:输入的单元
w:生成的w数组
return:w的地址
*/
void getwdata(unsigned char *s, struct wdata &w) {
  int i = 0;
  for (i; i < 16; ++i) {

    unsigned int t1 = *((unsigned int *)s + i);
    w.w[i] = ((t1 & 0xff) << 24) | (((t1 >> 8) & 0xff) << 16) |
             (((t1 >> 16) & 0xff) << 8) | ((t1 >> 24) & 0xff);
  }
  for (i; i < 80; ++i) {
    unsigned int t =
        (w.w[i - 3]) ^ (w.w[i - 8]) ^ (w.w[i - 14]) ^ (w.w[i - 16]);
    w.w[i] = lrot(t, 1);
  }
}
/*
gethash:获取每一步的哈希值
h:上一步的哈希值
w:生成的w数组
*/
void gethash(struct hash &h, const struct wdata &w) {
  unsigned int temph0 = h.h[0], temph1 = h.h[1], temph2 = h.h[2],
               temph3 = h.h[3], temph4 = h.h[4];
  unsigned int f, temp;
  unsigned int i = 0;
  for (i; i < 20; ++i) {
    f = (temph1 & temph2) | ((~temph1) & temph3);
    temp = lrot(temph0, 5) + f + 0x5A827999 + temph4 + w.w[i];
    temph4 = temph3;
    temph3 = temph2;
    temph2 = lrot(temph1, 30);
    temph1 = temph0;
    temph0 = temp;
  }
  for (i; i < 40; ++i) {
    f = temph1 ^ temph2 ^ temph3;
    temp = lrot(temph0, 5) + f + 0x6ED9EBA1 + temph4 + w.w[i];
    temph4 = temph3;
    temph3 = temph2;
    temph2 = lrot(temph1, 30);
    temph1 = temph0;
    temph0 = temp;
  }
  for (i; i < 60; ++i) {
    f = (temph1 & temph2) | (temph1 & temph3) | (temph2 & temph3);
    temp = lrot(temph0, 5) + f + 0x8F1BBCDC + temph4 + w.w[i];
    temph4 = temph3;
    temph3 = temph2;
    temph2 = lrot(temph1, 30);
    temph1 = temph0;
    temph0 = temp;
  }
  for (i; i < 80; ++i) {
    f = temph1 ^ temph2 ^ temph3;
    temp = lrot(temph0, 5) + f + 0xCA62C1D6 + temph4 + w.w[i];
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
getsha1f:获取文件的sha1哈希值
fp:输入文件
return:生成的sha1哈希序列
*/
unsigned char *getsha1f(FILE *fp) {

  if (fp == NULL)
    return NULL;
  struct hash h;
  h.h[0] = HASH0;
  h.h[1] = HASH1;
  h.h[2] = HASH2;
  h.h[3] = HASH3;
  h.h[4] = HASH4;

  unsigned char s1[64];
  int flag = 0;
  struct wdata w;
  for (unsigned int i = 0; flag != 2; ++i) {
    memset(s1, 0, sizeof(s1));
    unsigned sum = read_buffer64(fp, s1, &ibuf64);
    if (sum != 64 && flag == 0) {
      s1[sum] = 0x80u;
      sum++;
      flag = 1;
    }
    if (sum < 56) {
      unsigned long long b = (unsigned long long)i * 512 + (sum - 1) * 8;
      for (int i = 0; i < 8; ++i) {
        s1[56 + i] = ((b >> (7 - i) * 8) & 0xffu);
      }
      flag = 2;
    }
    getwdata(s1, w);
    gethash(h, w);
  }
  unsigned char *sha1res = (unsigned char *)malloc(20 * sizeof(unsigned char));
  for (int i = 0; i < 20; i++) {
    sha1res[i] = ((h.h[i / 4]) >> (8 * (3 - (i % 4)))) & 0x000000ffu;
  }
  return sha1res;
}
/*
接口函数
getsha1f:获取字符串的sha1哈希值
s:输入字符串
n:字符串长度
return:生成的sha1哈希序列
*/
unsigned char *getsha1s(unsigned char *s, unsigned int n) {
  struct hash h;
  h.h[0] = HASH0;
  h.h[1] = HASH1;
  h.h[2] = HASH2;
  h.h[3] = HASH3;
  h.h[4] = HASH4;

  unsigned long long b = n * 8, cnum;

  int flag = 0;

  if ((b + 8) % 512 >= 448)
    cnum = b / 512 + 2;
  else
    cnum = b / 512 + 1;

  unsigned char s1[64];
  struct wdata w;
  for (unsigned int i = 0; i < cnum; ++i) {
    memset(s1, 0, sizeof(s1));

    if ((i << 6) < n) {
      if (n - (i << 6) < 64) {
        memcpy(s1, s + (i << 6), n - (i << 6));
        s1[n - (i << 6)] = 0x80u;
        flag = 1;

      } else {
        memcpy(s1, s + (i << 6), 64);
      }
    } else if (!flag)
      s1[0] = 0x80u;
    if (i == cnum - 1) {
      for (int i = 0; i < 8; ++i) {
        s1[56 + i] = ((b >> (7 - i) * 8) & 0xffu);
      }
    }
    getwdata(s1, w);
    gethash(h, w);
  }
  unsigned char *sha1res = (unsigned char *)malloc(20 * sizeof(unsigned char));
  for (int i = 0; i < 20; ++i) {
    sha1res[i] = ((h.h[i / 4]) >> (8 * (3 - (i % 4)))) & 0x000000ffu;
  }
  return sha1res;
}