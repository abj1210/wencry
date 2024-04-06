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

#define FILE_MN_MARK 0
#define FILE_MODE_MARK 8
#define FILE_HMAC_MARK 10
#define FILE_IV_MARK 48
#define FILE_TEXT_MARK(threads_num) (48 + (20 * threads_num))
#define PADDING 38

/*计算HMAC类*/
class hmac
{
private:
  static const u8_t ipad = 0x36, opad = 0x5c;
  Hashmaster hashmaster;
  u8_t *hmac_res, type;
  void getres(u8_t *key, FILE *fp);

public:
  /*
  构造函数:设定哈希模式
  */
  hmac(u8_t hashtype) : type(hashtype), hashmaster(Hashmaster(Hashmaster::getType(hashtype)))
  {
    hmac_res = new u8_t[hashmaster.gethlen()];
  };
  ~hmac() { delete[] hmac_res; };
  void gethmac(u8_t *key, FILE *fp, u8_t *hmac_out);
  bool cmphmac(u8_t *key, FILE *fp, const u8_t *hmac_out);
  u8_t get_length() { return hashmaster.gethlen(); };
};
/*文件头处理类*/
class FileHeader
{
  // 魔数
  static const u64_t Magic_Num = 0xA5C3A5C3A5C3A5C3;
  u8_t hash[20], *key, num;
  u8_t ctype, htype;
  FILE *fp, *out;

public:
  FileHeader(FILE *fp, FILE *out, u8_t *key, u8_t ctype, u8_t htype, u8_t num) : fp(fp), out(out), key(key), ctype(ctype), htype(htype), num(num){};
  void getIV(const u8_t *r_buf, u8_t *iv);
  void getIV(FILE *fp, u8_t *iv);
  void getFileHeader(u8_t *iv);
  bool checkType();
  bool checkMn();
  u8_t *getHmac();
};

/*结果打印类*/
class ResultPrint
{
  bool no_echo;
  u8_t threads_num;

public:
  ResultPrint(u8_t threads_num, bool no_echo) : threads_num(threads_num), no_echo(no_echo){};
  u8_t printinv(const u8_t ret);
  void printtime(clock_t totalTime);
  void printenc();
  void printres(int res);
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
      char mode, ctype, htype;
      bool no_echo;
    };
    u8_t buf[512];
  } pakout_t;
  pakout_t *pakout;
  u8_t threads_num, iv[multicry_master::THREAD_MAX * 20];

  FileHeader header;
  GetCryMaster crym;
  hmac hmachandle;
  ResultPrint resultprint;

  void hashfile();
  void enc(const u8_t *r_buf);
  u8_t verify();
  u8_t dec();
  void over();

public:
  /*
      构造函数:设定各部件参数
  */
  runcrypt(u8_t *data, u8_t threads_num = THREAD_NUM);
  ~runcrypt() { delete pakout; };
  bool exec_val();
};

#endif