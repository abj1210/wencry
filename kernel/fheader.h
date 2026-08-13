#ifndef FHD
#define FHD

#include "hashmaster.h"
#include "display.h"
#include "display/console_display.h"
#include "display/silent_display.h"
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
计算HMAC类
*/

class hmac
{
  static const u8_t ipad = 0x36, opad = 0x5c;
  HashFactory hf;
  Display *res_printer;
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
  void loadprinter(Display *res_printer) { this->res_printer = res_printer; };
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
