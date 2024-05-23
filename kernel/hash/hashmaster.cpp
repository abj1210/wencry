#include "hashmaster.h"
#include <string.h>
/*################################
  哈希算法框架函数
################################*/

/*
getFileHash:返回文件哈希
fp:文件指针
hashres:结果哈希地址
*/
void Hashmaster::getFileHash(FILE *fp, u8_t *hashres)
{
  reset();
  hashbuf = new buffer64(fp);
  while (true)
  {
    u64_t sum = hashbuf->read_buffer64(hashblock);
    if (sum != 64)
    {
      getHash(hashblock, sum);
      break;
    }
    getHash(hashblock);
  }
  getres(hashres);
  delete hashbuf;
}
/*
getFileOffsetHash:返回拼接文件哈希
fp:文件指针
block:拼接块
hashres:结果哈希地址
*/
void Hashmaster::getFileOffsetHash(FILE *fp, u8_t *block, u8_t *hashres)
{
  reset();
  hashbuf = new buffer64(block, fp);
  while (true)
  {
    u64_t sum = hashbuf->read_buffer64(hashblock);
    if (sum != 64)
    {
      getHash(hashblock, sum);
      break;
    }
    getHash(hashblock);
  }
  getres(hashres);
  delete hashbuf;
}
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
return:返回的类型
*/
HashFactory::HASH_TYPE HashFactory::getType(u8_t type)
{
  switch (type)
  {
  case 0:
    return SHA1;
    break;
  case 1:
    return MD5;
    break;
  default:
    return Unknown;
    break;
  }
}
/*
getHasher:根据哈希类型返回相应的算法
type:哈希类型
return:返回的哈希类
*/
Hashmaster *HashFactory::getHasher(HashFactory::HASH_TYPE type)
{
  switch (type)
  {
  case HASH_TYPE::SHA1:
    return new sha1hash();
    break;
  case HASH_TYPE::MD5:
    return new md5hash();
    break;
  default:
    return NULL;
    break;
  }
}
/*
getHashLength:返回相应类型的哈希长度
type:哈希类型
return:哈希长度
*/
const u8_t HashFactory::getHashLength(HashFactory::HASH_TYPE type)
{
  switch (type)
  {
  case HASH_TYPE::SHA1:
    return sha1hash::gethlen();
    break;
  case HASH_TYPE::MD5:
    return md5hash::gethlen();
    break;
  default:
    return 0;
    break;
  }
}
/*
getBlkLength:返回相应类型的哈希块长度
type:哈希类型
return:块长度
*/
const u8_t HashFactory::getBlkLength(HashFactory::HASH_TYPE type)
{
  switch (type)
  {
  case HASH_TYPE::SHA1:
    return sha1hash::getblen();
    break;
  case HASH_TYPE::MD5:
    return md5hash::getblen();
    break;
  default:
    return 0;
    break;
  }
}