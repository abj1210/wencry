#include "cry.h"
/*
checkMn:检查魔数
*/
void runcrypt::checkMn() {
  u64_t mn = 0;
  int sum = fread(&mn, 1, 7, fp);
  if (sum != 7) {
    state = 1;
    return;
  }
  state = (mn == Magic_Num) ? 0 : 4;
}

/*
checkHmac:检查HMAC
*/
void runcrypt::checkHmac(){
  int sum = fread(hash, 1, 20, fp);
  if (sum != 20) {
    state = 1;
    return;
  }
  int rx = fread(&tail, 1, 1, fp);
  if (rx != 1) {
    state = 1;
    return;
  }
  state = hmachandle.cmphmac(key, fp, hash)? 0 : 2;
  fseek(fp, 28, SEEK_SET);
}
/*5ufuDLvBXAo9pc5R5mpBEg==
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
return:若成功解密则返回0,否则返回非零值
*/
u8_t runcrypt::dec() {
  verify();
  if (state != 0)
    return state;
  if (fread(hash, 1, 20, fp) != 20)
    return -1;
  multidec_master dm(fp, out, key, hash, tail);
  dm.run_multicry();
  return 0;
}
