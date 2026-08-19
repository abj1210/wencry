#include "hashmaster.h"
#include <string.h>

/*
getHash:处理末尾块(追加 0x80 填充与64位长度字段)
input:末尾块数据
final_loadsize:末尾块字节数
*/
void sha1hash::getHash(const u8_t *input, u32_t final_loadsize)
{
  addtotal(final_loadsize);
  u64_t bitlen = totalsize;
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
    temp[56 + i] = (u8_t)(bitlen >> ((7 - i) << 3));
  }
  getHash(temp);
  delete[] temp;
}
/*
接口函数
getres:获取哈希结果
hashout:输出字符串地址
*/
void sha1hash::getres(u8_t *hashout)
{
  for (int i = 0; i < 20; ++i)
    hashout[i] = (u8_t)((h[i >> 2]) >> ((3 - (i & 0x3)) << 3));
}