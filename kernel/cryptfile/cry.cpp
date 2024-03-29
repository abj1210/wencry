#include "cry.h"
/*################################
  HMAC函数
################################*/

/*
getres:计算HMAC值
key:密钥序列
fp:需验证文件指针
*/
void hmac::getres(u8_t *key, FILE *fp) {
  u8_t block = hashmaster.getblen(), length = hashmaster.gethlen();
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

/*################################
  加密辅助函数
################################*/
/*
getFileHeader:构造加密文件头
r_buf:随机缓冲数组
*/
void runcrypt::getFileHeader(const u8_t *r_buf) {
  u8_t padding[21];
  padding[20] = 0;
  u64_t mn = Magic_Num;
  fwrite(&mn, 1, 8, out);
  fwrite(padding, 1, 20, out);
  Hashmaster hm(Hashmaster::SHA1);
  hm.getStringHash(r_buf, strlen((const char *)r_buf), iv);
  fwrite(iv, 1, 20, out);
  for (int i = 1; i < multicry_master::THREADS_NUM; ++i) {
    hm.getStringHash(r_buf, strlen((const char *)r_buf), iv);
    fwrite(iv + (20 * i), 1, 20, out);
  }
}
/*
hashfile:计算文件的HMAC
*/
void runcrypt::hashfile() {
  fseek(out, 28, SEEK_SET);
  hmachandle.gethmac(key, out, hash);
  fseek(out, 8, SEEK_SET);
  fwrite(hash, 1, 20, out);
}


/*################################
  解密辅助函数
################################*/
/*
checkMn:检查魔数
*/
void runcrypt::checkMn() {
  u64_t mn = 0;
  int sum = fread(&mn, 1, 8, fp);
  if (sum != 8) {
    state = 1;
    return;
  }
  state = (mn == Magic_Num) ? 0 : 4;
}

/*
checkHmac:检查HMAC
*/
void runcrypt::checkHmac() {
  int sum = fread(hash, 1, 20, fp);
  if (sum != 20) {
    state = 1;
    return;
  }
  state = hmachandle.cmphmac(key, fp, hash) ? 0 : 2;
  fseek(fp, 28, SEEK_SET);
}


/*################################
  接口函数
################################*
/*
enc:将文件加密
r_buf:随机缓冲数组
ctype:加密模式
*/
void runcrypt::enc(const u8_t *r_buf, u8_t ctype) {
  getFileHeader(r_buf);
  multienc_master cm(fp, out, key, iv, ctype);
  cm.run_multicry();
  hashfile();
}
/*
dec:将文件解密
ctype:加密模式
return:若成功解密则返回0,否则返回非零值
*/
u8_t runcrypt::dec(u8_t ctype) {
  verify();
  if (state != 0)
    return state;
  for (int i = 0; i < multicry_master::THREADS_NUM; ++i) {
    if (fread(iv + (20 * i), 1, 20, fp) != 20)
      return -1;
  }
  multidec_master dm(fp, out, key, iv, ctype);
  dm.run_multicry();
  return 0;
}
/*
verify:验证密钥和文件
return:若为0则检查通过,否则检查不通过
*/
u8_t runcrypt::verify() {
  checkMn();
  if (state != 0)
    return state;
  checkHmac();
  return state;
}