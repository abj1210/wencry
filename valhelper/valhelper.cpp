#include "valhelper.h"
#include "base64.h"
#include <stdlib.h>
#include <stdio.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#elif defined(__linux__)
#include <sys/random.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
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

/*
wencry_fopen_read:以"二进制读 + 顺序访问提示"打开输入文件
见 valhelper.h 声明。
*/
FILE *wencry_fopen_read(const char *path)
{
#if defined(_WIN32)
  int fd = _open(path, _O_RDONLY | _O_BINARY | _O_SEQUENTIAL);
  if (fd < 0)
    return NULL;
  FILE *fp = _fdopen(fd, "rb");
  if (fp == NULL)
    _close(fd);
  return fp;
#else
  FILE *fp = fopen(path, "rb");
  if (fp != NULL)
    posix_fadvise(fileno(fp), 0, 0, POSIX_FADV_SEQUENTIAL);
  return fp;
#endif
}

/*
wencry_fopen_write:以"二进制写 + 顺序访问提示"打开输出文件
见 valhelper.h 声明。
*/
FILE *wencry_fopen_write(const char *path)
{
#if defined(_WIN32)
  int fd = _open(path, _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY | _O_SEQUENTIAL,
                 _S_IREAD | _S_IWRITE);
  if (fd < 0)
    return NULL;
  FILE *fp = _fdopen(fd, "wb");
  if (fp == NULL)
    _close(fd);
  return fp;
#else
  FILE *fp = fopen(path, "wb");
  if (fp != NULL)
    posix_fadvise(fileno(fp), 0, 0, POSIX_FADV_SEQUENTIAL);
  return fp;
#endif
}

/*
wencry_preallocate:设置文件大小(增长=预留,缩小=截断)
见 valhelper.h 声明。
*/
bool wencry_preallocate(FILE *fp, size_t size)
{
  if (fp == NULL)
    return true;
#if defined(_WIN32)
  HANDLE h = (HANDLE)_get_osfhandle(_fileno(fp));
  if (h == INVALID_HANDLE_VALUE)
    return false;
  LARGE_INTEGER zero, target;
  zero.QuadPart = 0;
  LARGE_INTEGER original;
  original.QuadPart = 0;
  // 记录并恢复文件指针位置,避免与 stdio 缓冲的位置跟踪冲突
  SetFilePointerEx(h, zero, &original, FILE_CURRENT);
  target.QuadPart = (LONGLONG)size;
  if (!SetFilePointerEx(h, target, NULL, FILE_BEGIN))
    return false;
  if (!SetEndOfFile(h))
    return false;
  SetFilePointerEx(h, original, NULL, FILE_BEGIN);
  return true;
#else
  return ftruncate(fileno(fp), (off_t)size) == 0;
#endif
}
