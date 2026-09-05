#include "cry.h"
#include "valhelper.h"
#include "display/console_display.h"
#include "display/silent_display.h"
#include <chrono>
#include <iostream>
#include <functional>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif
using namespace std;
using namespace chrono;

/*################################
  模块概述:加解密总流程(对外接口层)
  RunCrypt 类编排一次完整的文件加/解密:
    - 加密:生成IV并写文件头 -> 多线程AES流水线(写线程同时增量计算HMAC) -> 回填HMAC。
    - 解密:先验证(魔数/模式/HMAC,失败则不写任何输出) -> 按文件头记录的线程数解密 -> 输出。
    - 验证:仅做魔数/模式/HMAC检查。
  依赖:cry.h 中的 Settings(RunCrypt)/AesMode/AesFactory/MulticryMaster/BufferGroup/Hmac/FileHeader。
  TIMER_* 宏用于分段计时输出。
################################*/

/*################################
  宏定义和全局变量
################################*/
#define TIMER_START(timer) auto t_##timer = resultprint->createTimer(#timer);
#define TIMER_END(timer) resultprint->printTimer(t_##timer);
Settings default_settings;
/*################################
  辅助函数
################################*/
/*
设置选项类
*/
Settings::Settings(char ctype, char htype, bool no_echo) : ctype(ctype), htype(htype), no_echo(no_echo)
{
  if (ctype < -1 || ctype >= kCryptModeCount)
  {
    fprintf(stderr, "Invalid crypt type: %d\n", ctype);
    exit(1);
  }
  if (htype < -1 || htype >= kHashModeCount)
  {
    fprintf(stderr, "Invalid hash type: %d\n", htype);
    exit(1);
  }
}
void Settings::setCryptMode(char c)
{
  if (c < -1 || c >= kCryptModeCount)
  {
    fprintf(stderr, "Invalid crypt type: %d\n", c);
    exit(1);
  }
  else
    ctype = c;
};
void Settings::setHashMode(char h)
{
  if (h < -1 || h >= kHashModeCount)
  {
    fprintf(stderr, "Invalid hash type: %d\n", h);
    exit(1);
  }
  else
    htype = h;
};

/*
filePath:由FILE*反推文件路径(供解密失败删除输出文件)
fp:文件指针
return:文件路径(失败返回空串)
*/
static std::string filePath(FILE *fp)
{
#ifdef _WIN32
  HANDLE h = (HANDLE)_get_osfhandle(_fileno(fp));
  if (h == INVALID_HANDLE_VALUE)
    return "";
  wchar_t buf[4096];
  DWORD n = GetFinalPathNameByHandleW(h, buf, 4096, 0);
  if (n == 0 || n >= 4096)
    return "";
  int len = WideCharToMultiByte(CP_UTF8, 0, buf, (int)n, NULL, 0, NULL, NULL);
  std::string s((size_t)len, '\0');
  WideCharToMultiByte(CP_UTF8, 0, buf, (int)n, &s[0], len, NULL, NULL);
  // 去掉 "\\?\" 前缀,便于 CRT remove()
  if (s.compare(0, 4, "\\\\?\\") == 0)
    s = s.substr(4);
  return s;
#else
  char buf[4096];
  char link[64];
  snprintf(link, sizeof(link), "/proc/self/fd/%d", fileno(fp));
  ssize_t n = readlink(link, buf, sizeof(buf) - 1);
  if (n <= 0)
    return "";
  buf[n] = '\0';
  return std::string(buf);
#endif
}

/*
prepareIv:准备初始向量
r_buf:随机缓冲数组
r_len:随机缓冲有效字节数
return:初始向量地址
*/
u8_t *RunCrypt::prepareIv(const u8_t *r_buf, size_t r_len)
{
  u8_t *iv = new u8_t[MulticryMaster::THREAD_MAX * 20];
  header.getIv(r_buf, r_len, iv);
  header.writeFileHeader(iv);
  return iv;
}
/*
prepareIv:准备初始向量
return:初始向量地址
*/
u8_t *RunCrypt::prepareIv()
{
  u8_t *iv = new u8_t[MulticryMaster::THREAD_MAX * 20];
  header.getIv(fin, iv);
  return iv;
}
/*
checkHeader:校验文件头结构与读取存储的HMAC(不读密文)
hlen_out:输出HMAC长度
hash_out:输出存储HMAC指针(指向FileHeader内部缓冲,在解密/验证期间保持有效)
return:0=通过,1=文件过短,3=加密/哈希模式非法,4=魔数错误
*/
u8_t RunCrypt::checkHeader(u8_t &hlen_out, u8_t *&hash_out)
{
  resultprint->printTask("Checking file header");
  // 结构校验(魔数/模式/长度),返回值即为 res 码(1=文件过短,3=模式非法,4=魔数错误)
  int hc = header.checkHeader();
  if (hc != 0)
    return (u8_t)hc;
  header.checkType(); // 读取 ctype/htype/线程数(含旧格式回退4)
  resultprint->printCryptMode(header.getCryptMode());
  resultprint->printHashMode(header.getHashMode());
  // HMAC 长度随 htype 为 16/20/32,只读取实际长度(避免读入填充/IV区)。
  u8_t hlen = 32;
  switch (header.getHashMode())
  {
  case 0:
    hlen = 20;
    break;
  case 1:
    hlen = 16;
    break;
  default:
    hlen = 32;
    break;
  }
  u8_t *hash = header.getHmac(hlen);
  if (hash == NULL)
    return 1;
  hlen_out = hlen;
  hash_out = hash;
  return 0;
}
/*
prepareAes:准备缓冲区和aes加密器
ctype:加密模式
iv:初始向量
cmode:模式(true:加密,false:解密)
return:加密器地址组
*/
AesMode **RunCrypt::prepareAes(u8_t ctype, u8_t *iv, bool cmode)
{
  // 解密时输入指针已由 prepareIv()->getIv(FILE*) 定位到 FILE_TEXT_MARK,
  // 此处无需再 fseek(见 executeDecrypt 调用顺序)。
  AesMode **mode = new AesMode *[threads_num];
  for (int i = 0; i < threads_num; i++)
    mode[i] = aesfactory.createCryMaster(cmode, ctype, iv + 20 * i);
  return mode;
}
/*
prepareCrypter:为流水线注入 AES回调、HMAC 喂入回调与进度回调
aesmode:AES加密器组
file_size:文件大小
pipemode:流水线模式(加密/解密/验证)
*/
void RunCrypt::prepareCrypter(AesMode ** aesmode ,size_t file_size ,pipe_mode pipemode){
  BufferGroup *buffer = BufferGroup::getInstance();
  buffer->setBufferGroup(threads_num, pipemode);
  mtmaster.setHashType(header.getHashMode());
  crym.setHashSize(mtmaster.getHashSize());
  crym.setMerkleTreeCallback([this](const u8_t * d, size_t id){mtmaster.addBlockHmac(id,d);});
  crym.setProgressCallback([this, file_size](std::string name, size_t now_size) { resultprint->printPercentage(name, now_size, file_size ? file_size : 1); });
  for(int i = 0; i < threads_num; i++){
    crym.setHmacCallback([this, i](const u8_t *d, u8_t *o, size_t n, size_t id) {
      u8_t prefix[9];
      mtmaster.getLeafPrefix(id, prefix);
      hmachandle[i].getHmac((u8_t)header.getHashMode(), key, d, o, n, prefix, mtmaster.getPrefixLen());
    }, i);
    if(aesmode == NULL)
      crym.setAesCallback(nullptr, i);
    else
      crym.setAesCallback([aesmode, i](u8_t * b) { aesmode[i]->runCrypt(b); }, i);
  }
}
void RunCrypt::getRootHmac(u8_t * buf, u8_t * iv, u8_t n){
  u8_t * temp = (u8_t *)malloc(sizeof(u8_t)*mtmaster.getHashSize());
  size_t total_blocks = mtmaster.getTopHash(buf);
  hmachandle[0].getHmac(header.getHashMode(), key, buf, temp, mtmaster.getHashSize(), mtmaster.getRootPrefix(total_blocks, iv, n), mtmaster.getPrefixLen()+(20*n));
  memcpy(buf, temp, mtmaster.getHashSize());
  free(temp);
}
/*
release:释放空间
iv:初始向量
mode:加密器地址组
*/
void RunCrypt::release(u8_t *iv, AesMode **mode, u8_t * buf)
{
  crym.setMerkleTreeCallback(nullptr);
  crym.setProgressCallback(nullptr);
  for(int i = 0; i < threads_num; i++){
    crym.setAesCallback(nullptr, i);
    crym.setHmacCallback(nullptr, i);
  }
  resultprint->resetPercentage();
  BufferGroup::delInstance();
  delete[] iv;
  free(buf);
  if(mode!= NULL){
    for (int i = 0; i < threads_num; i++)
      delete mode[i];
    delete[] mode;
  }
}
/*
closeFiles:关闭文件并释放空间
*/
void RunCrypt::closeFiles()
{
  if (fin != NULL)
    fclose(fin);
  if (out != NULL)
    fclose(out);
}

/*################################
  接口函数
################################*/
/*
构造函数
fin:输入文件指针
out:输出文件指针
key:密钥
settings:加解密参数
threads_num:线程数
*/
/* 将工作线程数限制在 [1, THREAD_MAX],非法值回退到默认 THREAD_NUM。 */
u8_t RunCrypt::clampThreadNum(u8_t n)
{
  if (n == 0 || n > MulticryMaster::THREAD_MAX)
    return THREAD_NUM;
  return n;
}
RunCrypt::RunCrypt(FILE *fin, FILE *out, u8_t *key, Settings settings, u8_t threads_num)
    : fin(fin), out(out), key(key), settings(settings), threads_num(RunCrypt::clampThreadNum(threads_num)),
      header(fin, out, key, settings.getCryptMode(), settings.getHashMode(), RunCrypt::clampThreadNum(threads_num)),
      aesfactory(key), crym(fin, out)
{
  if (settings.getNoEcho())
    resultprint = new SilentDisplay;
  else
    resultprint = new ConsoleDisplay;
  hmachandle = new Hmac[threads_num];
};
/*
析构函数
*/
RunCrypt::~RunCrypt() {
	if (resultprint != nullptr) {
		delete resultprint;
		resultprint = nullptr;
	}
  delete[] hmachandle;
}
/*
executeEncrypt:加密执行过程
fsize:文件大小
r_buf:随机缓冲数组
r_len:随机缓冲有效字节数
*/
void RunCrypt::executeEncrypt(size_t fsize, u8_t *r_buf, size_t r_len)
{
  if (fin == NULL)
    throw std::string("Invalid File");
  TIMER_START(Total_Time);

  // 预留输出文件大小(文件头 + PKCS7 后的密文),避免边写边扩展带来的碎片/元数据开销
  if (out != NULL)
  {
    size_t out_size = (size_t)FILE_TEXT_MARK(threads_num) + (((size_t)fsize >> 4) + 1) * 16;
    wencryPreallocate(out, out_size);
  }


  // 准备初始化
  resultprint->printTask("Preparing encrypt");
  u8_t *iv = prepareIv(r_buf, r_len);
  AesMode **mode = prepareAes(settings.getCryptMode(), iv, true);
  prepareCrypter(mode, fsize, PIPE_ENCRYPT);
  u8_t * buf = (u8_t *)malloc(sizeof(u8_t)*mtmaster.getHashSize());


  // 运行加密(写线程导出密文时同步喂入HMAC,避免回读)
  TIMER_START(AES_Encryption_Time)
  resultprint->printTask("Encrypting");
  crym.runMulticry(threads_num, PIPE_ENCRYPT);
  TIMER_END(AES_Encryption_Time)


  // 完成Hmac并写入
  resultprint->printTask("Writing Hmac");
  getRootHmac(buf, iv, threads_num);
  header.writeHmac(buf, mtmaster.getHashSize(), FILE_HMAC_MARK);


  // 释放空间
  resultprint->printTask("Releasing allocated memory");
  release(iv, mode, buf);
  resultprint->printEncryptDone(); // 打印结果
  closeFiles();                  // 关闭文件
  TIMER_END(Total_Time);   // 打印时间
}
/*
executeDecrypt:解密执行过程
fsize:文件大小
return:高8位-哈希模式 低8位-加密模式
*/
unsigned short RunCrypt::executeDecrypt(size_t fsize)
{
  if (fin == NULL)
    throw std::string("Invalid File");
  if (key == NULL)
    throw std::string("Invalid Key");
  TIMER_START(Total_Time);


  // 结构校验(魔数/模式/线程数/长度,不读密文)
  u8_t hlen = 0;
  u8_t *stored = NULL;
  int res = checkHeader(hlen, stored);
  if (res != 0)
  {
    resultprint->printDecryptResult(res);
    closeFiles();
    TIMER_END(Total_Time);
    throw resultprint->getResultString(res);
  }


  // 准备初始化
  resultprint->printTask("Preparing decrypt");
  threads_num = header.getThreadNum();
  // 纵深防御:线程数必须落在 [1, THREAD_MAX],防止越界写 threads[] / IV 缓冲
  if (threads_num == 0 || threads_num > MulticryMaster::THREAD_MAX)
    threads_num = THREAD_NUM;
  u8_t *iv = prepareIv();
  AesMode **mode = prepareAes(header.getCryptMode(), iv, false);
  prepareCrypter(mode, fsize, PIPE_DECRYPT);
  u8_t * buf = (u8_t *)malloc(sizeof(u8_t)*mtmaster.getHashSize());

  // 预留输出空间(上界=密文长度),避免解密写出时反复扩展文件
  if (out != NULL)
  {
    size_t hdr = (size_t)FILE_TEXT_MARK(threads_num);
    size_t cipher_size = (fsize >= hdr) ? (fsize - hdr) : 0;
    wencryPreallocate(out, cipher_size);
  }


  // 融合解密:读密文时HASH线程增量计算HMAC(消除独立验证读)
  TIMER_START(AES_Decryption_Time)
  resultprint->printTask("Decrypting & verifying");
  crym.runMulticry(threads_num, PIPE_DECRYPT);
  TIMER_END(AES_Decryption_Time)

  // 按实际写出的明文长度截断(去掉预分配的上界余量)
  if (out != NULL)
  {
    fflush(out);
    wencryPreallocate(out, crym.getWrittenBytes());
  }


  // 完成HMAC并与文件头存储值比对
  resultprint->printTask("Comparing HMAC");
  getRootHmac(buf, iv, threads_num);
  bool hmac_ok = hmachandle[0].matchResult(stored, hlen, buf);


  // 释放空间
  resultprint->printTask("Releasing allocated memory");
  release(iv, mode, buf);
  if (!hmac_ok)
  {
    std::string outpath = filePath(out);
    resultprint->printDecryptResult(2);
    closeFiles();
    TIMER_END(Total_Time);
    if (!outpath.empty())
      remove(outpath.c_str()); // 失败删除输出文件
    throw resultprint->getResultString(2);
  }
  resultprint->printDecryptResult(0); // 打印结果
  closeFiles();                     // 关闭文件
  TIMER_END(Total_Time);      // 打印时间
  return header.getHashMode() << 8 | header.getCryptMode();
}
/*
executeVerify:验证执行过程
fsize:文件大小
return:高8位-哈希模式 低8位-加密模式
*/
unsigned short RunCrypt::executeVerify(size_t fsize)
{
  if (fin == NULL)
    throw std::string("Invalid File");
  if (key == NULL)
    throw std::string("Invalid Key");
  TIMER_START(Total_Time);


  // 结构校验
  u8_t hlen = 0;
  u8_t *stored = NULL;
  int res = checkHeader(hlen, stored);
  if (res != 0)
  {
    resultprint->printVerifyResult(res);
    closeFiles();
    TIMER_END(Total_Time);
    throw resultprint->getResultString(res);
  }


  // 用统一流水线读+哈希(不AES不写)
  resultprint->printTask("Preparing Verification");
  threads_num = header.getThreadNum();
  // 纵深防御:线程数必须落在 [1, THREAD_MAX]
  if (threads_num == 0 || threads_num > MulticryMaster::THREAD_MAX)
    threads_num = THREAD_NUM;
  u8_t *iv = prepareIv(); // 读IV,fin定位到FILE_TEXT_MARK
  prepareCrypter(nullptr, fsize, PIPE_VERIFY);
  u8_t * buf = (u8_t *)malloc(sizeof(u8_t)*mtmaster.getHashSize());


  TIMER_START(AES_Hashing_Time)
  resultprint->printTask("Computing HMAC");
  crym.runMulticry(threads_num, PIPE_VERIFY);
  TIMER_END(AES_Hashing_Time)

  resultprint->printTask("Comparing HMAC");
  getRootHmac(buf, iv, threads_num);
  bool hmac_ok = hmachandle[0].matchResult(stored, hlen, buf);


  resultprint->printTask("Releasing allocated memory");
  release(iv, NULL, buf);
  if (!hmac_ok)
    res = 2;
  resultprint->printVerifyResult(res); // 打印结果
  closeFiles();                      // 关闭文件
  TIMER_END(Total_Time);       // 打印时间
  if (res != 0)
    throw resultprint->getResultString(res);
  return header.getHashMode() << 8 | header.getCryptMode();
}
/*
get_percentage:获取进度
return: -1表示已完成, 0-100表示进度
*/

int RunCrypt::getPercentageGui()
{
  if (resultprint->isOver())
    return -1;
  return resultprint->getPercentage();
};

/*################################
  分配/释放工厂
################################*/
/*
createRunCrypt:按库自身 sizeof(RunCrypt) 分配并构造
fin:输入文件
out:输出文件
key:密钥
settings:加解密参数
threads_num:工作线程数(默认 THREAD_NUM)
return:新分配的 RunCrypt 对象
*/
RunCrypt *createRunCrypt(FILE *fin, FILE *out, u8_t *key, const Settings& settings, u8_t threads_num)
{
  return new RunCrypt(fin, out, key, settings, threads_num);
}
/*
destroyRunCrypt:释放 RunCrypt 对象
r:待释放对象
*/
void destroyRunCrypt(RunCrypt *r)
{
  delete r;
}
