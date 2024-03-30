#ifndef CRY
#define CRY
#include "multicry.h"
#include "hashmaster.h"
#include <stdio.h>
#include <string.h>
typedef unsigned char u8_t;
typedef unsigned long long u64_t;

#define THREAD_NUM 4
#define GET_VAL(data, val) (((pakout_t *)data)->val)

/*计算HMAC类*/
class hmac
{
private:
  static const u8_t ipad = 0x36, opad = 0x5c;
  Hashmaster hashmaster;
  u8_t *hmac_res;
  void getres(u8_t *key, FILE *fp);

public:
  /*
  构造函数:设定哈希模式
  */
  hmac(u8_t hashtype) : hashmaster(Hashmaster(Hashmaster::getType(hashtype)))
  {
    hmac_res = new u8_t[hashmaster.gethlen()];
  };
  ~hmac() { delete[] hmac_res; };
  void gethmac(u8_t *key, FILE *fp, u8_t *hmac_out);
  bool cmphmac(u8_t *key, FILE *fp, const u8_t *hmac_out);
};
/*文件头处理类*/
class FileHeader
{
  // 魔数
  static const u64_t Magic_Num = 0xA5C3A5C3A5C3A5C3;
  u8_t hash[20], *key, num;
  FILE *fp, *out;

public:
  FileHeader(FILE *fp, FILE *out, u8_t *key, u8_t num) : fp(fp), out(out), key(key), num(num){};
  void getIV(const u8_t *r_buf, u8_t *iv);
  void getIV(FILE *fp, u8_t *iv);
  void getFileHeader(u8_t *iv);
  bool checkMn();
  u8_t *getHmac();
};

/*整体加密类*/
class runcrypt
{
  /*
  参数包结构体
  */
  typedef union
  {
    struct
    {
      FILE *fp, *out;
      u8_t *key;
      u8_t r_buf[256];
      char mode, ctype;
      bool no_echo;
    };
    u8_t buf[512];
  } pakout_t;

  char mode;
  u8_t state, thread_num, iv[multicry_master::THREAD_MAX * 20];
  u8_t *key, *r_buf;
  FILE *fp, *out;
  bool no_echo;
  FileHeader header;
  multienc_master cm;
  multidec_master dm;
  hmac hmachandle;
  void hashfile();
  void enc(const u8_t *r_buf);
  u8_t verify();
  u8_t dec();

  u8_t printinv(const u8_t ret);
  void printtime(clock_t totalTime, u8_t threads_num);
  void printenc();
  void printres(int res);
  void over();

public:
  /*
      构造函数:设定各部件参数
      fp:输入文件指针
      out:输出文件指针
      key:初始密钥序列
      ctype:加密模式
      no_echo:是否打印输出
      thread_num:线程数
  */
  runcrypt(u8_t *data);
  bool exec_val();
};

#endif