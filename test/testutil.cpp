#include "testutil.h"
#include <string.h>
#include <atomic>

#ifdef _WIN32
#include <process.h>
#define GETPID _getpid
#else
#include <unistd.h>
#define GETPID getpid
#endif

/*
make_tmp_name:生成跨进程唯一的临时文件名
out:输出缓冲区
cap:缓冲区大小
tag:文件名标签
*/
void make_tmp_name(char *out, size_t cap, const char *tag)
{
  static std::atomic<unsigned> cnt(0);
  unsigned id = cnt.fetch_add(1);
  snprintf(out, cap, "wt_%d_%u_%s", (int)GETPID(), id, tag);
}

/*
genfile:生成临时文件并写入字符串 str,返回只读文件句柄
str:写入文件的内容
return:以只读方式打开的文件句柄(由调用方关闭)
*/
FILE *genfile(const char *str)
{
  static char prev_name[64];
  if (prev_name[0] != '\0')
    remove(prev_name);
  char name[64];
  make_tmp_name(name, sizeof(name), "gen");
  snprintf(prev_name, sizeof(prev_name), "%s", name);
  FILE *fp = fopen(name, "wb");
  fputs(str, fp);
  fclose(fp);
  fp = fopen(name, "rb");
  return fp;
}
/*
write_pattern_file:写入确定性内容的测试文件
fname:文件名
size:文件大小
*/
void write_pattern_file(const char *fname, size_t size)
{
  FILE *fp = fopen(fname, "wb");
  if (fp == NULL)
    return;
  unsigned char buf[4096];
  size_t left = size, off = 0;
  while (left)
  {
    size_t n = left < sizeof(buf) ? left : sizeof(buf);
    for (size_t i = 0; i < n; ++i)
      buf[i] = (unsigned char)((off + i) % 251);
    fwrite(buf, 1, n, fp);
    off += n;
    left -= n;
  }
  fclose(fp);
}
/*
gethex:将十六进制字符串解析为字节数组
str:十六进制字符串(每两位一个字节)
out:解析输出的字节数组
*/
void gethex(const char *str, unsigned char *out)
{
  int hex = -1;
  size_t j = 0;
  for (size_t i = 0; i < strlen(str); ++i)
  {
    if (hex == -1)
    {
      if (str[i] >= '0' && str[i] <= '9')
        hex = str[i] - '0';
      else if (str[i] >= 'a' && str[i] <= 'f')
        hex = str[i] - 'a' + 10;
      else if (str[i] >= 'A' && str[i] <= 'F')
        hex = str[i] - 'A' + 10;
    }
    else
    {
      hex = hex << 4;
      if (str[i] >= '0' && str[i] <= '9')
        hex += str[i] - '0';
      else if (str[i] >= 'a' && str[i] <= 'f')
        hex += str[i] - 'a' + 10;
      else if (str[i] >= 'A' && str[i] <= 'F')
        hex += str[i] - 'A' + 10;
      out[j++] = hex & 0xff;
      hex = -1;
    }
  }
}
/*
cmpstr:逐字节比较两段内存前 n 字节是否一致
s1/s2:待比较内存
n:比较字节数
return:全部一致返回 true,否则 false
*/
bool cmpstr(const unsigned char *s1, const unsigned char *s2, int n)
{
  for (int i = 0; i < n; i++)
  {
    printf("%d: 0x%02x 0x%02x\n", i, s1[i], s2[i]);
    if (s1[i] != s2[i])
      return false;
  }
  return true;
}
