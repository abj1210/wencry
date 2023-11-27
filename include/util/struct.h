#ifndef STU
#define STU

#include <stdio.h>
/*
state:用于aes操作的基本单元
s:16B数据
*/
struct state {
  union {
    struct {
      unsigned long long datal, datah;
    };
    unsigned int g[4];
    unsigned char s[4][4];
  };
};

union byteint {
  unsigned int i;
  struct {
    unsigned char t0, t1, t2, t3;
  };
};
/*
vpak:参数包
fp:输入文件
out:输出文件
key:初始密钥
mode:模式(加密/解密)
*/
struct vpak {
  FILE *fp, *out;
  unsigned char *key;
  char mode;
};
/*
wdata:sha1生成的w数组
w:320B数据
*/
struct wdata {
  unsigned w[80];
};
/*
hash:sha1的hash基本单元
h:20B数据
*/
struct hash {
  unsigned h[5];
};

#endif