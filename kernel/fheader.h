#ifndef FHD
#define FHD

#include "hashmaster.h"
#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <string.h>
#include <chrono>
#include <atomic>

typedef unsigned char u8_t;
typedef unsigned long long u64_t;

/*
文件头处理类
*/
class FileHeader
{
  static const u64_t Magic_Num = 0xA5C3A5C3A5C3A5C3;
  u8_t hash[64], *key, num;
  u8_t ctype, htype;
  FILE *fp, *out;
  HashFactory hf;

public:
   FileHeader(FILE* fp, FILE* out, u8_t* key, u8_t num) : key(key), num(num), ctype(-1), htype(-1), fp(fp), out(out) { memset(hash, 0, sizeof(hash)); };
  FileHeader(FILE *fp, FILE *out, u8_t *key, u8_t ctype, u8_t htype, u8_t num) : key(key), num(num), ctype(ctype), htype(htype), fp(fp), out(out) { memset(hash, 0, sizeof(hash)); };
  void getIV(const u8_t *r_buf, u8_t *iv);
  void getIV(FILE *fp, u8_t *iv);
  void getFileHeader(u8_t *iv);
  void checkType();
  u8_t getctype() const { return ctype; };
  u8_t gethtype() const { return htype; };
  u8_t get_num() const { return num; };
  bool checkMn();
  u8_t *getHmac(u8_t len);
};

/*
计时器类
*/

struct Timer
{
  std::chrono::system_clock::time_point start;
  std::string name;
};

/*
结果打印类
*/

class AbsResultPrint
{
protected:
  std::atomic<size_t> acc_size;
  std::atomic<size_t> total_size;
  std::atomic<bool> over;

public:
  AbsResultPrint() : acc_size(0), total_size(1), over(false) {};
  virtual ~AbsResultPrint() {};
  virtual void printtask(std::string name) = 0;
  virtual u8_t printinv(const u8_t ret) = 0;
  virtual Timer *createTimer(std::string name) = 0;
  virtual void printTimer(Timer *timer) = 0;
  virtual void printenc() = 0;
  virtual void printresd(int res) = 0;
  virtual void printresv(int res) = 0;
  virtual void printctype(u8_t type) = 0;
  virtual void printhtype(u8_t type) = 0;
  virtual void printpercentage(std::string name, size_t now_size, size_t total_size) = 0;
  virtual void resetPercentage();
  std::string getResStr(int res){
    if (res <= 0)
        return "Verification passed!";
    else if (res == 1)
        return "Input file is too short.";
    else if (res == 2)
        return "Wrong key or File not complete.";
    else if (res == 3)
        return "Aes / hash mode not match.";
    else if (res == 4)
        return "Wrong magic number.";
    else
        return "Unknown res number: " + std::to_string(res);
  }
  int getPercentage() const
  {
    size_t t = total_size.load();
    size_t a = acc_size.load();
    if (t == 0)
      return 0;
    int p = (int)(100 * ((double)a / (double)t));
    if (p < 0)
      p = 0;
    if (p > 100)
      p = 100;
    return p;
  };
  bool isOver() const { return over.load(); };
};

class NullResPrint : public AbsResultPrint
{
public:
    NullResPrint() : AbsResultPrint() {};
  virtual void printtask(std::string) {};
  virtual u8_t printinv(const u8_t ret) { return ret; };
  virtual Timer *createTimer(std::string) { return NULL; };
  virtual void printTimer(Timer *) {};
  virtual void printenc() { over.store(true); };
  virtual void printresd(int) { over.store(true); };
  virtual void printresv(int) { over.store(true); };
  virtual void printctype(u8_t) {};
  virtual void printhtype(u8_t) {};
  virtual void resetPercentage() override { acc_size.store(0); };
  virtual void printpercentage(std::string, size_t now_size, size_t total_size)
  {
    this->total_size.store(total_size);
    this->acc_size.fetch_add(now_size);
  };
};

class ResultPrint : public AbsResultPrint
{

  void strlog(std::string s1, std::string s2, char fill = ' ')
  {
    std::cout << std::setw(40) << std::setfill(fill) << std::left << s1 << std::setfill(fill) << std::setw(40) << std::right << s2 << "\r\n";
  }

public:
    ResultPrint() : AbsResultPrint() {};
  virtual void printtask(std::string name);
  virtual u8_t printinv(const u8_t ret);
  virtual Timer *createTimer(std::string name);
  virtual void printTimer(Timer *timer);
  virtual void printenc();
  virtual void printresd(int res);
  virtual void printresv(int res);
  virtual void printctype(u8_t type);
  virtual void printhtype(u8_t type);
  virtual void resetPercentage() override;
  virtual void printpercentage(std::string name, size_t now_size, size_t total_size);
};

/*
计算HMAC类
*/

class hmac
{
  static const u8_t ipad = 0x36, opad = 0x5c;
  HashFactory hf;
  AbsResultPrint *res_printer;
  u8_t *hmac_res, length;
  void getres(u8_t hashtype, u8_t *key, FILE *fp, size_t fsize);

  // 增量HMAC(加密融合路径)使用的状态
  Hashmaster *hashmaster;
  u8_t *key1, *h1;
  u8_t accum[64];
  u8_t block_len, accum_len;

  void clear_incr();

public:
  hmac();
  ~hmac();
  void loadprinter(AbsResultPrint *res_printer) { this->res_printer = res_printer; };
  void gethmac(u8_t hashtype, u8_t *key, FILE *fp, u8_t *hmac_out, size_t fsize = 0);
  bool cmphmac(u8_t hashtype, u8_t *key, FILE *fp, const u8_t *hmac_out, size_t fsize = 0);
  /*
  增量HMAC(加密/解密/验证融合时计算,避免回读密文)
  init_hash:初始化,喂入ipad块与prefix(文件头IV区)
  feed_hash:喂入密文块
  final_hash:完成计算,结果存于hmac_res
  write_hmac:将hmac_res写入文件指定偏移
  match_result:final_hash 后与给定摘要比较
  */
  void init_hash(u8_t hashtype, u8_t *key, const u8_t *prefix, size_t prefix_len);
  void feed_hash(const u8_t *data, size_t len);
  void final_hash();
  void write_hmac(FILE *fp, u8_t writeMark);
  bool match_result(const u8_t *expected, u8_t len) const;
};

#endif
