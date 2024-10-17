#ifndef CRY
#define CRY
#include "multicry.h"
#include "fheader.h"

#include <stdio.h>
#include <string.h>
typedef unsigned char u8_t;
typedef unsigned long long u64_t;

#define THREAD_NUM 4
#define FILE_MN_MARK 0
#define FILE_MODE_MARK 8
#define FILE_HMAC_MARK 10
#define FILE_IV_MARK 48
#define FILE_TEXT_MARK(threads_num) (48 + (20 * threads_num))
#define PADDING 38
/*
加密模式设置类
*/
class Settings
{
  char ctype, htype;
  bool no_echo;

public:
  Settings() : ctype(1), htype(0), no_echo(false) {};
  Settings(char ctype, char htype, bool no_echo);
  /*
  set_ctype:设置加密模式
  - 0:电子密码本ECB
  - 1:密码块链CBC
  - 2:计数器模式CTR
  - 3:密文反馈CFB
  - 4:输出反馈OFB
  */
  void set_ctype(char c);
  /*
  set_htype:设置哈希模式
  - 0:sha1
  - 1:md5
  - 2:sha256
  */
  void set_htype(char h);
  /*
  set_no_echo:设置回显模式
  */
  void set_no_echo(bool no_echo) { no_echo = no_echo; };
  char get_ctype() const { return ctype; };
  char get_htype() const { return htype; };
  bool get_no_echo() const { return no_echo; };
};
extern Settings default_settings;

/*
整体加密类
*/
class runcrypt
{
  FILE *fin, *out;
  u8_t *key;
  Settings settings;
  const u8_t threads_num;
  bool mode;

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

  u8_t *prepare_IV(const u8_t *r_buf);
  u8_t *prepare_IV();
  Aesmode **prepare_AES(u8_t *iv, size_t fsize, bool mode);
  void release(u8_t *iv, Aesmode **mode);
  u8_t verify(size_t fsize);
  void over();

public:
  runcrypt(FILE *fin, FILE *out, u8_t *key, Settings settings = default_settings, u8_t threads_num = THREAD_NUM);
  ~runcrypt() { delete resultprint; };
  bool execute_encrypt(size_t fsize, u8_t *r_buf = NULL);
  bool execute_decrypt(size_t fsize);
  bool execute_verify(size_t fsize);
  int get_percentage();
};

#endif