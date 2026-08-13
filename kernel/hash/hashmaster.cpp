#include "hashmaster.h"
#include "sha_ni.h"
#include <string.h>
/*################################
  哈希算法框架函数
################################*/

/*
getStringHash:返回字符串哈希
string:字符串指针
length:长度
hashres:结果哈希地址
*/
void Hashmaster::getStringHash(const u8_t *string, u32_t length,
                               u8_t *hashres)
{
  reset();
  u32_t nnow = length;
  for (; nnow >= 64; nnow -= 64)
    getHash(string + (length - nnow));
  getHash(string + (length - nnow), nnow);
  getres(hashres);
}

/*################################
  哈希工厂函数
################################*/

/*
getType:根据数字返回哈希类型
type:输入的数字
return:返回的类型(非法返回 HT_COUNT 哨兵)
*/
HashType HashFactory::getType(u8_t type)
{
  switch (type)
  {
  case HT_SHA1:
    return HT_SHA1;
  case HT_MD5:
    return HT_MD5;
  case HT_SHA256:
    return HT_SHA256;
  default:
    return HT_COUNT;
  }
}
/*
getHasher:根据哈希类型返回相应的算法
type:哈希类型
return:返回的哈希类
*/
Hashmaster *HashFactory::getHasher(HashType type)
{
  switch (type)
  {
  case HT_SHA1:
    return new sha1ni();
  case HT_MD5:
    return new md5hash();
  case HT_SHA256:
    return new sha256ni();
  default:
    return NULL;
  }
}