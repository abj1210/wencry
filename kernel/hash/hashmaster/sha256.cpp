#include "hashmaster.h"
#include <string.h>

/*
模块概述:SHA256 公共逻辑
Sha256Hash 只保留末尾块填充、长度字段写入与摘要输出等与硬件无关的公共部分;
64字节整块压缩由派生类 Sha256Ni 在 sha_ni.cpp 中用 SHA-NI 指令完成。
*/

/*
getHash:处理末尾块(追加 0x80 填充与64位长度字段)
input:末尾块数据
final_loadsize:末尾块字节数
*/
void Sha256Hash::getHash(const u8_t *input, u32_t final_loadsize)
{
  addTotalLength(final_loadsize);
  u64_t bitlen = totalsize;
  u8_t *temp = new u8_t[getBlockLength()];
  memset(temp, 0, getBlockLength());
  memcpy(temp, input, final_loadsize);
  temp[final_loadsize] = 0x80u;
  if (final_loadsize >= 56)
  {
    getHash(temp);
    memset(temp, 0, getBlockLength());
  }
  for (int i = 0; i < 8; ++i)
  {
    temp[56 + i] = (u8_t)((bitlen >> ((7 - i) << 3)));
  }
  getHash(temp);
  delete[] temp;
}
/*
接口函数
computeResult:获取哈希结果
hashout:输出字符串地址
*/
void Sha256Hash::computeResult(u8_t *hashout)
{
  for (int i = 0; i < 32; ++i)
    hashout[i] = (u8_t)((h[i >> 2]) >> ((3 - (i & 0x3)) << 3));
}
