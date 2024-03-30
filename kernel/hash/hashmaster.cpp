#include "hashmaster.h"
#include <string.h>
/*
getType:根据数字返回哈希类型
type:输入的数字
return:返回的类型
*/
Hashmaster::HASH_TYPE Hashmaster::getType(u8_t type) {
  switch (type) {
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
Hashmaster::Hashmaster(HASH_TYPE type) : type(type) {
  switch (type) {
  case SHA1:
    hasher = new sha1hash();
    break;
  default:
    hasher = NULL;
    break;
  }
};
/*
getFileHash:返回文件哈希
fp:文件指针
hashres:结果哈希地址
*/
void Hashmaster::getFileHash(FILE *fp, u8_t *hashres) {
  hasher->reset();
  hashbuf = new buffer64(fp);
  while (true) {
    u64_t sum = hashbuf->read_buffer64(hasher->getLoadAddr());
    if (sum != 64) {
      hasher->finalHash(sum);
      break;
    }
    hasher->gethash();
  }
  hasher->getres(hashres);
  delete hashbuf;
}
/*
getFileOffsetHash:返回拼接文件哈希
fp:文件指针
block:拼接块
hashres:结果哈希地址
*/
void Hashmaster::getFileOffsetHash(FILE *fp, u8_t *block, u8_t *hashres) {
  hasher->reset();
  hashbuf = new buffer64(block, fp);
  while (true) {
    u64_t sum = hashbuf->read_buffer64(hasher->getLoadAddr());
    if (sum != 64) {
      hasher->finalHash(sum);
      break;
    }
    hasher->gethash();
  }
  hasher->getres(hashres);
  delete hashbuf;
}
/*
getStringHash:返回字符串哈希
string:字符串指针
length:长度
hashres:结果哈希地址
*/
void Hashmaster::getStringHash(const u8_t *string, u32_t length,
                               u8_t *hashres) {
  hasher->reset();
  u32_t nnow = length;
  for (; nnow >= 64; nnow -= 64) {
    memcpy(hasher->getLoadAddr(), string + (length - nnow), 64);
    hasher->gethash();
  }
  memcpy(hasher->getLoadAddr(), string + (length - nnow), nnow);
  hasher->finalHash(nnow);
  hasher->getres(hashres);
}