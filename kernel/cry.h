#ifndef CRY
#define CRY
#include "multicry.h"
#include "aesmode.h"
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
ctype:加密模式
htype:哈希模式
no_echo:是否隐藏输出
*/
class Settings
{
  char ctype, htype;
  bool no_echo;

public:
  /* Settings:默认构造,缺省 CBC(1)+SHA1(0)+显示输出 */
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
  void set_no_echo(bool no_echo) { this->no_echo = no_echo; };
  /* get_ctype:获取加密模式 */
  char get_ctype() const { return ctype; };
  /* get_htype:获取哈希模式 */
  char get_htype() const { return htype; };
  /* get_no_echo:获取是否隐藏输出 */
  bool get_no_echo() const { return no_echo; };
};
extern Settings default_settings;

/*
runcrypt:文件加解密和验证整体处理类
runcrypt整合了文件头解析、AES加解密工厂、并发调度器、hmac计算器和结果打印器。其接口函数将参数准备、并发处理、hmac处理和释放空间四个任务线性地执行。
*/
class runcrypt
{
  FILE *fin, *out;        // 输入输出文件指针
  u8_t *key;              // 密钥
  Settings settings;      // 加解密模式设置类
  u8_t threads_num;       // 工作线程数

  FileHeader header;      // 文件头构造器
  AesFactory aesfactory;  // aes加解密工厂
  multicry_master crym;   // 并发加解密器
  hmac hmachandle;        // hmac计算器
  Display *resultprint;   // 结果打印器

  u8_t *prepare_IV(const u8_t *r_buf, size_t r_len);
  u8_t *prepare_IV();
  u8_t check_header(u8_t &hlen, u8_t *&hash);
  Aesmode **prepare_AES(u8_t ctype, u8_t *iv, bool mode);
  void prepare_cryption_master(Aesmode ** aesmode, size_t file_size, pipe_mode pipemode);
  void release(u8_t *iv, Aesmode **mode);
  void over();
  

  runcrypt(FILE *fin, FILE *out, u8_t *key, Settings settings = default_settings, u8_t threads_num = THREAD_NUM);
  ~runcrypt();

public:
  friend runcrypt *runcrypt_create(FILE *fin, FILE *out, u8_t *key, const Settings& settings, u8_t threads_num);
  friend void runcrypt_destroy(runcrypt *r);
  void execute_encrypt(size_t fsize, u8_t *r_buf = NULL, size_t r_len = 0);
  unsigned short execute_decrypt(size_t fsize);
  unsigned short execute_verify(size_t fsize);
  int get_percentage_gui();
};

/*
分配/释放工厂:由内核库按自身 sizeof(runcrypt) 分配。
GUI 等外部模块只持有 runcrypt* 指针,不直接 new/delete,
避免头文件版本不一致导致的对象尺寸不匹配(越界写穿)。
*/
runcrypt *runcrypt_create(FILE *fin, FILE *out, u8_t *key, const Settings& settings, u8_t threads_num = THREAD_NUM);
void runcrypt_destroy(runcrypt *r);

#endif
