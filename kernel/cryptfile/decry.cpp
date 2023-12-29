#include "cry.h"
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
/*
接口函数
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
/*
接口函数
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
