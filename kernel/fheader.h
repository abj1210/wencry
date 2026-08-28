#ifndef FHD
#define FHD

#include "merkletree.h"
#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <string.h>
#include <chrono>
#include <atomic>

typedef unsigned char u8_t;
typedef unsigned long long u64_t;

/*
FileHeader:文件头处理类
FileHeader用于生成和解析加密文件的文件头，为runcrypt类提供调用接口。
*/
class FileHeader
{
  static const u64_t Magic_Num = 0xA5C3A5C3A5C3A5C3; // 文件头魔数(8字节)
  u8_t hash[64];        // HMAC缓冲区(校验/写入文件头用)
  u8_t *key, num;       // 密钥、工作线程数
  u8_t ctype, htype;    // 加密模式、哈希模式
  FILE *fp, *out;       // 输入/输出文件
  HashFactory hf;       // 哈希工厂(按 htype 生成 HMAC 哈希器)

public:
  /* FileHeader:解密/验证用构造(ctype/htype 待从文件头读取,-1 表示未知) */
  FileHeader(FILE* fp, FILE* out, u8_t* key, u8_t num) : key(key), num(num), ctype(-1), htype(-1), fp(fp), out(out) { memset(hash, 0, sizeof(hash)); };
  /* FileHeader:加密用构造(显式指定 ctype/htype) */
  FileHeader(FILE *fp, FILE *out, u8_t *key, u8_t ctype, u8_t htype, u8_t num) : key(key), num(num), ctype(ctype), htype(htype), fp(fp), out(out) { memset(hash, 0, sizeof(hash)); };
  void getIV(const u8_t *r_buf, size_t r_len, u8_t *iv);
  void getIV(FILE *fp, u8_t *iv);
  void getFileHeader(u8_t *iv);
  int check_header();
  void write_hmac(u8_t *hmac, size_t hsize, u8_t writeMark);
  void checkType();
  /* getctype:获取加密模式 */
  u8_t getctype() const { return ctype; };
  /* gethtype:获取哈希模式 */
  u8_t gethtype() const { return htype; };
  /* get_num:获取工作线程数 */
  u8_t get_num() const { return num; };
  u8_t *getHmac(u8_t len);
};
#endif
