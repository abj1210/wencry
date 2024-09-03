#ifndef FHD
#define FHD

#include "hashmaster.h"
#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <string.h>

typedef unsigned char u8_t;
typedef unsigned long long u64_t;

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
  hmac(u8_t hashtype) : type(hf.getType(hashtype)) {};
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
  FileHeader(FILE *fp, FILE *out, u8_t *key, u8_t ctype, u8_t htype, u8_t num) : fp(fp), out(out), key(key), ctype(ctype), htype(htype), num(num) {};
  void getIV(const u8_t *r_buf, u8_t *iv);
  void getIV(FILE *fp, u8_t *iv);
  void getFileHeader(u8_t *iv);
  bool checkType();
  bool checkMn();
  u8_t *getHmac(u8_t len);
};
/*计时器类*/
struct Timer
{
  std::chrono::_V2::system_clock::time_point start;
  std::string name;
};

/*结果打印类*/
class AbsResultPrint
{
public:
  virtual void printtask(std::string name) = 0;
  virtual u8_t printinv(const u8_t ret) = 0;
  virtual Timer *createTimer(std::string name) = 0;
  virtual void printTimer(Timer *timer) = 0;
  virtual void printenc() = 0;
  virtual void printres(int res) = 0;
};

class NullResPrint : public AbsResultPrint
{
public:
  virtual void printtask(std::string name) {};
  virtual u8_t printinv(const u8_t ret) { return ret; };
  virtual Timer *createTimer(std::string name) { return NULL; };
  virtual void printTimer(Timer *timer) {};
  virtual void printenc() {};
  virtual void printres(int res) {};
};

class ResultPrint : public AbsResultPrint
{
  void strlog(std::string s1, std::string s2, char fill = ' ')
  {
    std::cout << std::setw(40) << std::setfill(fill) << std::left << s1 << std::setfill(fill) << std::setw(40) << std::right << s2 << std::endl;
  }

public:
  virtual void printtask(std::string name);
  virtual u8_t printinv(const u8_t ret);
  virtual Timer *createTimer(std::string name);
  virtual void printTimer(Timer *timer);
  virtual void printenc();
  virtual void printres(int res);
};

#endif