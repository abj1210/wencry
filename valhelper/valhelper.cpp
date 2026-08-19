#include "valhelper.h"
#include "base64.h"
#include <stdlib.h>
#include <stdio.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <sys/random.h>
#include <errno.h>
#endif

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
csprng_fill:用操作系统加密安全随机源填充缓冲区(跨平台)
buf:输出缓冲
len:字节数
Windows 用 BCryptGenRandom(系统首选 RNG),Linux 优先 getrandom,/dev/urandom 作
POSIX 回退;随机源不可用时打印错误并终止(加密工具无法在无熵源下安全继续)。
*/
static void csprng_fill(u8_t *buf, size_t len)
{
  if (len == 0)
    return;
#if defined(_WIN32)
  if (BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0)
    return;
#elif defined(__linux__)
  size_t off = 0;
  while (off < len)
  {
    ssize_t n = getrandom(buf + off, len - off, 0);
    if (n > 0)
    {
      off += (size_t)n;
      continue;
    }
    if (n < 0 && errno == EINTR)
      continue;
    break;
  }
  if (off == len)
    return;
#endif
#if !defined(_WIN32)
  FILE *f = fopen("/dev/urandom", "rb");
  if (f != NULL)
  {
    size_t got = fread(buf, 1, len, f);
    fclose(f);
    if (got == len)
      return;
  }
#endif
  fprintf(stderr, "Error: system random source unavailable\n");
  exit(1);
}
/*
getRandomKey:获取随机密钥
return:返回的密钥
*/
u8_t *getRandomKey()
{
  u8_t *keyout = new u8_t[16];
  csprng_fill(keyout, 16);
  return keyout;
}
/*
getRandomBuffer:获取随机的缓冲数组
r_buf:缓冲数组地址
*/
void getRandomBuffer(u8_t *r_buf)
{
  csprng_fill(r_buf, 256);
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