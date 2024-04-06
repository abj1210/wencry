#include "aesmode.h"
/*
selectCryptMode:返回相应的加密器
key:密钥
iv:初始向量
type:类型(0:ECB,1:CBC,2:CTR,3:CFB,4:OFB)
return:返回的加密器
*/
Aesmode *selectCryptMode(u8_t *key, const u8_t *iv, u8_t type)
{
  switch (type)
  {
  case 0:
    return new AesECB(key, iv);
  case 1:
    return new AesCBC(key, iv);
  case 2:
    return new AesCTR(key, iv);
  case 3:
    return new AesCFB(key, iv);
  case 4:
    return new AesOFB(key, iv);
  default:
    printf("Unknown\n");
    return NULL;
  }
}
/*
  resetIV:重设初始向量
  */
void Aesmode::resetIV(u8_t *iv)
{
  memcpy(this->initiv, iv, 16);
  resetIV();
};
void Aesmode::resetIV() { memcpy(this->iv, this->initiv, 16); };
/*
getXor:获取异或值
x:被异或值
mask:异或掩码
*/
void Aesmode::getXor(u8_t *x, u8_t *mask)
{
  for (int i = 0; i < 16; ++i)
    x[i] = x[i] ^ mask[i];
}
void AesCBC::getencry(u8_t *block)
{
  getXor(block, iv);
  encryhandle.runaes_128bit(block);
  memcpy(iv, block, 16);
}
void AesCBC::getdecry(u8_t *block)
{
  u8_t nxt_iv[16];
  memcpy(nxt_iv, block, 16);
  decryhandle.runaes_128bit(block);
  getXor(block, iv);
  memcpy(iv, nxt_iv, 16);
}
void AesCTR::ctrInc()
{
  for (int i = 15; i >= 0; i--)
  {
    iv[i]++;
    if (iv[i] != 0)
      break;
  }
}
void AesCTR::getencry(u8_t *block)
{
  u8_t mask[16];
  memcpy(mask, iv, 16);
  encryhandle.runaes_128bit(mask);
  getXor(block, mask);
  ctrInc();
}
void AesCFB::getencry(u8_t *block)
{
  encryhandle.runaes_128bit(iv);
  getXor(block, iv);
  memcpy(iv, block, 16);
}
void AesCFB::getdecry(u8_t *block)
{
  u8_t nxt_iv[16];
  memcpy(nxt_iv, block, 16);
  encryhandle.runaes_128bit(iv);
  getXor(block, iv);
  memcpy(iv, nxt_iv, 16);
}
void AesOFB::getencry(u8_t *block)
{
  encryhandle.runaes_128bit(iv);
  getXor(block, iv);
}