#include "hashmaster.h"
#include <string.h>
#include <assert.h>
#define CHOOSE(e, f, g) ((e & f) ^ (~e & g))
#define MAJORITY(a, b, c) ((a & b) ^ (a & c) ^ (b & c))
#define SIGMA0(x) (rrot(x, 2) ^ rrot(x, 13) ^ rrot(x, 22))
#define SIGMA1(x) (rrot(x, 6) ^ rrot(x, 11) ^ rrot(x, 25))
#define GAMMA0(x) (rrot(x, 7) ^ rrot(x, 18) ^ (x >> 3))
#define GAMMA1(x) (rrot(x, 17) ^ rrot(x, 19) ^ (x >> 10))

const u32_t sha256hash::k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
/*
getwdata:根据每个输入单元生成sha1中w数组的值
*/
void sha256hash::getwdata()
{
  u32_t t, t1, t2, i = 0;
  for (i; i < 16; ++i)
  {
    t = this->i[i];
    w[i] = setbytes(((u8_t)(t >> 24)), ((u8_t)(t >> 16)), ((u8_t)(t >> 8)), t);
  }
  for (i; i < 64; ++i)
  {
    t1 = w[i - 2];
    t2 = w[i - 15];
    w[i] = GAMMA1(t1) + w[i - 7] + GAMMA0(t2) + w[i - 16];
  }
}
/*
gethash:获取每一步的哈希值
*/
void sha256hash::getHash(const u8_t *input)
{
  memset(s, 0, sizeof(s));
  memcpy(s, input, sizeof(s));
  getwdata();
  addtotal(64);
  u32_t temph[8];
  memcpy(temph, h, sizeof(h));
  for (u32_t i = 0; i < 64; ++i)
  {
    u32_t t1 = temph[7] + SIGMA1(temph[4]) + CHOOSE(temph[4], temph[5], temph[6]) + k[i] + w[i];
    u32_t t2 = SIGMA0(temph[0]) + MAJORITY(temph[0], temph[1], temph[2]);
    fflush(stdout);
    temph[7] = temph[6];
    temph[6] = temph[5];
    temph[5] = temph[4];
    temph[4] = temph[3] + t1;
    temph[3] = temph[2];
    temph[2] = temph[1];
    temph[1] = temph[0];
    temph[0] = t1 + t2;
  }
  for (u32_t i = 0; i < 8; ++i)
    h[i] += temph[i];
}

/*
finalHash:结尾的哈希处理
loadsize:装载字节数
*/
void sha256hash::getHash(const u8_t *input, u32_t final_loadsize)
{
  addtotal(final_loadsize);
  u8_t *temp = new u8_t[getblen()];
  memset(temp, 0, getblen());
  memcpy(temp, input, final_loadsize);
  temp[final_loadsize] = 0x80u;
  if (final_loadsize >= 56)
  {
    getHash(temp);
    memset(temp, 0, getblen());
  }
  for (int i = 0; i < 8; ++i)
  {
    temp[56 + i] = (u8_t)(((u64_t)totalsize >> ((7 - i) << 3)));
  }
  getHash(temp);
  delete[] temp;
}
/*
接口函数
getres:获取哈希结果
hashout:输出字符串地址
*/
void sha256hash::getres(u8_t *hashout)
{
  for (int i = 0; i < 32; ++i)
    hashout[i] = (u8_t)((h[i >> 2]) >> ((3 - (i & 0x3)) << 3));
}