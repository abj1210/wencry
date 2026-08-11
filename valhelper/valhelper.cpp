#include "valhelper.h"
#include "base64.h"
#include <iostream>
#include <iomanip>
#include <stdlib.h>


/*
strlog:格式化打印两段信息(左侧40字符宽左对齐,右侧40字符宽右对齐)
s1:左侧信息
s2:右侧信息
fill:填充字符(默认空格)
*/
void strlog(std::string s1, std::string s2, char fill)
{
  std::cout << std::setw(40) << std::setfill(fill) << std::left << s1 << std::setfill(fill) << std::setw(40) << std::right << s2 << std::endl;
}
/*
printkey:将16字节密钥转换为base64字符串
key:16字节密钥
return:base64编码后的密钥串
*/
std::string printkey(u8_t *key)
{
  char outk[128];
  hex_to_base64(key, 16, (u8_t *)outk);
  std::string skey = outk;
  return skey;
}
/*
checkB64Key:校验base64密钥串并解码为16字节密钥
b64key:base64输入串
key:解码输出的16字节密钥
return:合法(24字符且解码为16字节)返回true,否则false
*/
bool checkB64Key(const u8_t* b64key, u8_t *key){
  if(!is_valid_b64(b64key, strlen((char *)b64key)))
    return false;
  else{
    base64_to_hex(b64key, 24, key);
    return true;
  }
}
/*
getRandomKey:获取随机密钥
return:返回的密钥
*/
u8_t *getRandomKey()
{
  srand(time(NULL));
  u8_t *keyout = new u8_t[16];
  for (int i = 0; i < 16; ++i)
    keyout[i] = rand();
  return keyout;
}
/*
getRandomBuffer:获取随机的缓冲数组
r_buf:缓冲数组地址
*/
void getRandomBuffer(u8_t *r_buf)
{
    for (int i = 0; i < 256; ++i)
        r_buf[i] = rand();
}
/*
getProcessMode:将模式字符映射为任务编号
mode:模式字符(e/E加密,d/D解密,v验证)
return:0=加密,1=解密,2=验证,其他=-1
*/
int getProcessMode(char mode){
  if (mode == 'e' || mode == 'E')
    return 0;
  else if (mode == 'd' || mode == 'D')
    return 1;
  else if (mode == 'v')
    return 2;
  else
    return -1;
}