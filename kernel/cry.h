#ifndef CRY
#define CRY
#include "multicry.h"
#include "hashmaster.h"
#include <iostream>
#include <iomanip>
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
  static const u8_t ipad = 0x36, opad = 0x5c;
  HashFactory hf;
  HashFactory::HASH_TYPE type;
  u8_t *hmac_res, length;
  void getres(u8_t *key, FILE *fp);

public:
  /*
  构造函数:设定哈希模式
  */
  hmac(u8_t hashtype) : type(hf.getType(hashtype)){};
  void gethmac(u8_t *key, FILE *fp, u8_t *hmac_out);
  bool cmphmac(u8_t *key, FILE *fp, const u8_t *hmac_out);
  void writeFileHmac(FILE *fp, u8_t *key, u8_t hashMark, u8_t writeMark);
  const u8_t get_length() { return length; };
};
/*文件头处理类*/
class FileHeader
{
  // 魔数
  static const u64_t Magic_Num = 0xA5C3A5C3A5C3A5C3;
  u8_t hash[64], *key, num;
  u8_t ctype, htype;
  FILE *fp, *out;
  HashFactory hf;

public:
  FileHeader(FILE *fp, FILE *out, u8_t *key, u8_t ctype, u8_t htype, u8_t num) : fp(fp), out(out), key(key), ctype(ctype), htype(htype), num(num){};
  void getIV(const u8_t *r_buf, u8_t *iv);
  void getIV(FILE *fp, u8_t *iv);
  void getFileHeader(u8_t *iv);
  bool checkType();
  bool checkMn();
  u8_t *getHmac(u8_t len);
};

struct Timer{
  std::chrono::_V2::system_clock::time_point start;
  std::string name;
};

/*结果打印类*/
class AbsResultPrint
{
public:
  virtual void printtask(std::string name) = 0;
  virtual u8_t printinv(const u8_t ret) = 0;
  virtual Timer * createTimer(std::string name) = 0;
  virtual void printTimer(Timer * timer) = 0;
  virtual void printenc() = 0;
  virtual void printres(int res) = 0;
};

class NullResPrint : public AbsResultPrint
{
public:
  virtual void printtask(std::string name){};
  virtual u8_t printinv(const u8_t ret) { return ret; };
  virtual Timer * createTimer(std::string name) {return NULL; };
  virtual void printTimer(Timer * timer){};
  virtual void printenc() {};
  virtual void printres(int res) {};
};

class ResultPrint : public AbsResultPrint
{
  void strlog(std::string s1, std::string s2, char fill = ' '){
    std::cout << std::setw(40) << std::setfill(fill)<< std::left << s1 << std::setfill(fill) << std::setw(40) << std::right << s2 << std::endl;
  }
public:
  virtual void printtask(std::string name);
  virtual u8_t printinv(const u8_t ret);
  virtual Timer * createTimer(std::string name);
  virtual void printTimer(Timer * timer);
  virtual void printenc();
  virtual void printres(int res);
};

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
    size_t size;
    char mode, ctype, htype;
    bool no_echo;
  };
  u8_t buf[512];
} pakout_t;

/*整体加密类*/
class runcrypt
{
  pakout_t *pakout;
  const u8_t threads_num;

  // 文件头构造器
  FileHeader header;
  // aes加解密工厂
  AesFactory aesfactory;
  // 并发加解密器
  multicry_master crym;
  // hmac计算器
  hmac hmachandle;
  // 结果打印器
  AbsResultPrint *resultprint;

  void enc(const u8_t *r_buf);
  u8_t verify();
  u8_t dec();
  void over();

public:
  runcrypt(u8_t *data, u8_t threads_num = THREAD_NUM);
  ~runcrypt()
  {
    delete pakout;
    delete resultprint;
  };
  bool exec_val();
};

#endif