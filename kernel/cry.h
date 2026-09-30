#ifndef CRY
#define CRY
#include "multicry.h"
#include "aesmode.h"
#include "fheader.h"
#include "display.h"

#include <stdio.h>
typedef unsigned char u8_t;
typedef unsigned long long u64_t;

#ifndef THREAD_NUM
#define THREAD_NUM 4
#endif
#define FILE_MN_MARK 0
#define FILE_MODE_MARK 8
#define FILE_HMAC_MARK 10
#define FILE_IV_MARK 48
#define FILE_TEXT_MARK(threads_num) (48 + (20 * (threads_num)))
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
  setCryptMode:设置加密模式
  - 0:电子密码本ECB
  - 1:密码块链CBC
  - 2:计数器模式CTR
  - 3:密文反馈CFB
  - 4:输出反馈OFB
  */
  void setCryptMode(char c);
  /*
  setHashMode:设置哈希模式
  - 0:sha1
  - 1:md5
  - 2:sha256
  */
  void setHashMode(char h);
  /*
  setNoEcho:设置回显模式
  */
  void setNoEcho(bool no_echo) { this->no_echo = no_echo; };
  /* getCryptMode:获取加密模式 */
  char getCryptMode() const { return ctype; };
  /* getHashMode:获取哈希模式 */
  char getHashMode() const { return htype; };
  /* getNoEcho:获取是否隐藏输出 */
  bool getNoEcho() const { return no_echo; };
};
extern Settings default_settings;

/*
RunCrypt:文件加解密和验证整体处理类
RunCrypt整合了文件头解析、AES加解密工厂、并发调度器、Hmac计算器和结果打印器。其接口函数将参数准备、并发处理、Hmac处理和释放空间四个任务线性地执行。
*/
class RunCrypt
{
  FILE *fin, *out;        // 输入输出文件指针
  u8_t *key;              // 密钥
  Settings settings;      // 加解密模式设置类
  u8_t threads_num;       // 工作线程数

  FileHeader header;      // 文件头构造器
  AesFactory aesfactory;  // aes加解密工厂
  MulticryMaster crym;   // 并发加解密器
  Hmac *hmachandle;        // Hmac计算器
  MerkleTreeMaster mtmaster;//merkle tree构建器
  Display *resultprint;   // 结果打印器

  u8_t *prepareIv(const u8_t *r_buf, size_t r_len);
  u8_t *prepareIv();
  u8_t checkHeader(u8_t &hlen, u8_t *&hash);
  AesMode **prepareAes(u8_t ctype, u8_t *iv, bool mode);
  void prepareCrypter(AesMode ** aesmode, size_t file_size, pipe_mode pipemode);
  void getRootHmac(u8_t * buf, u8_t * iv, u8_t n);
  void release(u8_t *iv, AesMode **mode, u8_t * buf);
  void closeFiles();
  /* clampThreadNum:将工作线程数限制在 [1, THREAD_MAX],非法值回退到默认 THREAD_NUM。 */
  static u8_t clampThreadNum(u8_t n);
   

  RunCrypt(FILE *fin, FILE *out, u8_t *key, Settings settings = default_settings, u8_t threads_num = THREAD_NUM);
  ~RunCrypt();

public:
  friend RunCrypt *createRunCrypt(FILE *fin, FILE *out, u8_t *key, const Settings& settings, u8_t threads_num);
  friend void destroyRunCrypt(RunCrypt *r);
  void executeEncrypt(size_t fsize, u8_t *r_buf = NULL, size_t r_len = 0);
  unsigned short executeDecrypt(size_t fsize);
  unsigned short executeVerify(size_t fsize);
  int getPercentageGui();
};

/*
分配/释放工厂:由内核库按自身 sizeof(RunCrypt) 分配。
GUI 等外部模块只持有 RunCrypt* 指针,不直接 new/delete,
避免头文件版本不一致导致的对象尺寸不匹配(越界写穿)。
*/
RunCrypt *createRunCrypt(FILE *fin, FILE *out, u8_t *key, const Settings& settings, u8_t threads_num = THREAD_NUM);
void destroyRunCrypt(RunCrypt *r);

#endif
