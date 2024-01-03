#include "hmac.h"
#include <string.h>
/*
getres:计算HMAC值
key:密钥序列
fp:需验证文件指针
*/
void hmac::getres(u8_t *key, FILE *fp) {
  u8_t block=hashmaster.getblen(), length=hashmaster.gethlen();
  u8_t key1[block], h1[block], h2[block + length];
  memset(key1, 0, sizeof(key1));
  memcpy(key1, key, 16);
  for (int i = 0; i < block; ++i)
    h1[i] = key1[i] ^ ipad;
  hashmaster.getFileOffsetHash(fp, h1, &h2[block]);
  for (int i = 0; i < block; ++i)
    h2[i] = key1[i] ^ opad;
  hashmaster.getStringHash(h2, block + length, hmac_res);
}
/*
gethmac:获取HMAC值
key:密钥序列
fp:需验证文件指针
hmac_out:输出地址
*/
void hmac::gethmac(u8_t *key, FILE *fp, u8_t *hmac_out) {
  getres(key, fp);
  memcpy(hmac_out, hmac_res, hashmaster.gethlen());
}
/*
cmphmac:校验HMAC值
key:密钥序列
fp:需验证文件指针
hmac_out:待校验的HMAC值
return:校验是否成功
*/
bool hmac::cmphmac(u8_t *key, FILE *fp, const u8_t *hmac_out) {
  getres(key, fp);
  for (int i = 0; i < hashmaster.gethlen(); ++i)
    if (hmac_out[i] != hmac_res[i])
      return false;
  return true;
}