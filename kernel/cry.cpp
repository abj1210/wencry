#include "cry.h"
#include <chrono>
#include <iostream>
#include <functional>
using namespace std;
using namespace chrono;

/*################################
  模块概述:加解密总流程(对外接口层)
  runcrypt 类编排一次完整的文件加/解密:
    - 加密:生成IV并写文件头 -> 多线程AES流水线(写线程同时增量计算HMAC) -> 回填HMAC。
    - 解密:先验证(魔数/模式/HMAC,失败则不写任何输出) -> 按文件头记录的线程数解密 -> 输出。
    - 验证:仅做魔数/模式/HMAC检查。
  依赖:cry.h 中的 Settings(runcrypt)/Aesmode/AesFactory/multicry_master/buffergroup/hmac/FileHeader。
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
  if (ctype < -1 || ctype > 4)
  {
    fprintf(stderr, "Invalid crypt type: %d\n", ctype);
    exit(1);
  }
  if (htype < -1 || htype > 2)
  {
    fprintf(stderr, "Invalid hash type: %d\n", htype);
    exit(1);
  }
}
void Settings::set_ctype(char c)
{
  if (c < -1 || c > 4)
  {
    fprintf(stderr, "Invalid crypt type: %d\n", c);
    exit(1);
  }
  else
    ctype = c;
};
void Settings::set_htype(char h)
{
  if (h < -1 || h > 2)
  {
    fprintf(stderr, "Invalid hash type: %d\n", h);
    exit(1);
  }
  else
    htype = h;
};

/*
prepare_IV:准备初始向量
r_buf:随机缓冲数组
return:初始向量地址
*/
u8_t *runcrypt::prepare_IV(const u8_t *r_buf)
{
  u8_t *iv = new u8_t[multicry_master::THREAD_MAX * 20];
  header.getIV(r_buf, iv);
  header.getFileHeader(iv);
  return iv;
}
/*
prepare_IV:准备初始向量
return:初始向量地址
*/
u8_t *runcrypt::prepare_IV()
{
  u8_t *iv = new u8_t[multicry_master::THREAD_MAX * 20];
  header.getIV(fin, iv);
  return iv;
}
/*
prepare_AES:准备缓冲区和aes加密器
ctype:加密模式
iv:初始向量
cmode:模式(true:加密,false:解密)
return:加密器地址组
*/
Aesmode **runcrypt::prepare_AES(u8_t ctype, u8_t *iv, bool cmode)
{
  // 解密时输入指针已由 prepare_IV()->getIV(FILE*) 定位到 FILE_TEXT_MARK,
  // 此处无需再 fseek(见 execute_decrypt 调用顺序)。
  buffergroup *iobuffer = buffergroup::get_instance();
  iobuffer->set_buffergroup(threads_num, fin, out, cmode);
  Aesmode **mode = new Aesmode *[threads_num];
  for (int i = 0; i < threads_num; i++)
    mode[i] = aesfactory.createCryMaster(cmode, ctype, iv + 20 * i);
  return mode;
}
/*
release:释放空间
iv:初始向量
mode:加密器地址组
*/
void runcrypt::release(u8_t *iv, Aesmode **mode)
{
  delete[] iv;
  for (int i = 0; i < threads_num; i++)
    delete mode[i];
  delete[] mode;
}
/*
over:关闭文件并释放空间
*/
void runcrypt::over()
{
  if (fin != NULL)
    fclose(fin);
  if (out != NULL)
    fclose(out);
}
/*
verify:验证密钥和文件
return:若为0则检查通过,否则检查不通过
*/
u8_t runcrypt::verify(size_t fsize)
{
  resultprint->printtask("Verifying file");
  // 结构校验(魔数/模式/线程数/长度)复用 wencry_check_header
  int hc = wencry_check_header(fin);
  if (hc == 1)
    return 4; // 魔数错误
  if (hc == 2)
    return 3; // 加密/哈希模式非法
  if (hc == 4)
    return 1; // 文件过短
  // hc==0 合法; hc==3 线程数越界,交由 checkType 回退处理
  header.checkType(); // 读取 ctype/htype/线程数(含旧格式回退4)
  resultprint->printctype(header.getctype());
  resultprint->printhtype(header.gethtype());
  // HMAC 长度随 htype 为 16/20/32,只读取实际长度(避免读入填充/IV区)。
  u8_t hlen = 32;
  switch (header.gethtype())
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
  fseek(fin, FILE_IV_MARK, SEEK_SET);
  if (!hmachandle.cmphmac(header.gethtype(), key, fin, hash, fsize))
    return 2;
  else
    return 0;
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
runcrypt::runcrypt(FILE *fin, FILE *out, u8_t *key, Settings settings, u8_t threads_num)
    : fin(fin), out(out), key(key), settings(settings), threads_num(threads_num), mode(false),
      header(fin, out, key, settings.get_ctype(), settings.get_htype(), threads_num),
      aesfactory(key)
{
  if (settings.get_no_echo())
    resultprint = new NullResPrint;
  else
    resultprint = new ResultPrint;
  hmachandle.loadprinter(resultprint);
};
/*
析构函数
*/
runcrypt::~runcrypt() {
	if (resultprint != nullptr) {
		delete resultprint;
		resultprint = nullptr;
	}
}
/*
execute_encrypt:加密执行过程
fsize:文件大小
r_buf:随机缓冲数组
*/
void runcrypt::execute_encrypt(size_t fsize, u8_t *r_buf)
{
  if (fin == NULL)
    throw std::string("Invalid File");
  TIMER_START(Total_Time);
  // 准备初始化
  resultprint->printtask("Preparing encrypt");
  u8_t *iv = prepare_IV(r_buf);
  Aesmode **mode = prepare_AES(settings.get_ctype(), iv, true);
  // 运行加密(写线程导出密文时同步喂入HMAC,避免回读)
  TIMER_START(AES_Encryption_Time)
  resultprint->printtask("Encrypting");
  hmachandle.init_hash(settings.get_htype(), key, iv, 20 * threads_num);
  buffergroup::get_instance()->set_hash_feed([this](const u8_t *d, size_t n) { hmachandle.feed_hash(d, n); });
  auto boundfunc = std::bind(&AbsResultPrint::printpercentage, resultprint, std::placeholders::_1, std::placeholders::_2, fsize == 0 ? 1 : fsize);
  crym.run_multicry(threads_num, mode, boundfunc);
  buffergroup::get_instance()->set_hash_feed(nullptr);
  resultprint->resetPercentage();
  buffergroup::del_instance();
  TIMER_END(AES_Encryption_Time)
  // 完成hmac并写入
  resultprint->printtask("Writing hmac");
  hmachandle.final_hash();
  hmachandle.write_hmac(out, FILE_HMAC_MARK);
  resultprint->resetPercentage();
  // 释放空间
  resultprint->printtask("Releasing allocated memory");
  release(iv, mode);
  resultprint->printenc(); // 打印结果
  over();                  // 关闭文件
  TIMER_END(Total_Time);   // 打印时间
}
/*
execute_decrypt:解密执行过程
fsize:文件大小
return:高8位-哈希模式 低8位-加密模式
*/
unsigned short runcrypt::execute_decrypt(size_t fsize)
{
  if (fin == NULL)
    throw std::string("Invalid File");
  TIMER_START(Total_Time);
  // 验证文件
  TIMER_START(Verify_Time);
  int res = verify(fsize);
  resultprint->resetPercentage();
  TIMER_END(Verify_Time);
  if (res == 0)
  {
    // 准备初始化
    resultprint->printtask("Preparing decrypt");
    threads_num = header.get_num();
    // 纵深防御:线程数必须落在 [1, THREAD_MAX],防止越界写 threads[] / IV 缓冲
    if (threads_num == 0 || threads_num > multicry_master::THREAD_MAX)
      threads_num = THREAD_NUM;
    u8_t *iv = prepare_IV();
    Aesmode **mode = prepare_AES(header.getctype(), iv, false);
    // 运行解密
    TIMER_START(AES_Decryption_Time)
    resultprint->printtask("Decrypting");
    auto boundfunc = std::bind(&AbsResultPrint::printpercentage, resultprint, std::placeholders::_1, std::placeholders::_2, fsize == 0 ? 1 : fsize);
    crym.run_multicry(threads_num, mode, boundfunc);
    resultprint->resetPercentage();
    TIMER_END(AES_Decryption_Time)
    // 释放空间
    resultprint->printtask("Releasing allocated memory");
    buffergroup::del_instance();
    release(iv, mode);
  }
  resultprint->printresd(res); // 打印结果
  over();                      // 关闭文件
  TIMER_END(Total_Time);       // 打印时间
  if(res!=0)
    throw resultprint->getResStr(res);
  return header.gethtype()<<8 | header.getctype();
}
/*
execute_verify:验证执行过程
fsize:文件大小
return:高8位-哈希模式 低8位-加密模式
*/
unsigned short runcrypt::execute_verify(size_t fsize)
{
  if (fin == NULL)
    throw std::string("Invalid File");
  TIMER_START(Total_Time);
  // 验证文件
  TIMER_START(Verify_Time);
  int res = verify(fsize);
  resultprint->resetPercentage();
  TIMER_END(Verify_Time);
  resultprint->printresv(res); // 打印结果
  over();                      // 关闭文件
  TIMER_END(Total_Time);       // 打印时间
  if(res!= 0)
    throw resultprint->getResStr(res);
  return header.gethtype()<<8 | header.getctype();
}
/*
get_percentage:获取进度
return: -1表示已完成, 0-100表示进度
*/

int runcrypt::get_percentage_gui()
{
  if (resultprint->isOver())
    return -1;
  return resultprint->getPercentage();
};

/*################################
  分配/释放工厂
################################*/
/*
runcrypt_create:按库自身 sizeof(runcrypt) 分配并构造
fin:输入文件
out:输出文件
key:密钥
return:新分配的 runcrypt 对象
*/
runcrypt *runcrypt_create(FILE *fin, FILE *out, u8_t *key, const Settings& settings)
{
  return new runcrypt(fin, out, key, settings);
}
/*
runcrypt_destroy:释放 runcrypt 对象
r:待释放对象
*/
void runcrypt_destroy(runcrypt *r)
{
  delete r;
}

/*################################
  文件头校验
################################*/
/*
wencry_check_header:校验 .wenc 文件头
魔数、加密模式(ctype<=4)、哈希模式(htype<=2)、线程数(1..THREAD_MAX)。
线程数字节为0表示旧格式文件(隐式4线程),视为合法。
fp:文件指针(函数不改变其读写位置)
return:0=合法,1=魔数错误,2=加密/哈希模式非法,3=线程数越界(>THREAD_MAX),4=文件过短
*/
int wencry_check_header(FILE *fp)
{
  if (fp == NULL)
    return 1;
  long pos = ftell(fp);
  rewind(fp);
  u8_t hdr[48];
  size_t rd = fread(hdr, 1, sizeof(hdr), fp);
  fseek(fp, pos, SEEK_SET);
  if (rd < sizeof(hdr))
    return 4;
  // Magic_Num = 0xA5C3A5C3A5C3A5C3,小端写入磁盘的字节序为 C3 A5 C3 A5 C3 A5 C3 A5
  static const u8_t magic[8] = {0xC3, 0xA5, 0xC3, 0xA5, 0xC3, 0xA5, 0xC3, 0xA5};
  if (memcmp(hdr, magic, 8) != 0)
    return 1;
  if (hdr[8] > 4 || hdr[9] > 2)
    return 2;
  if (hdr[47] > multicry_master::THREAD_MAX)
    return 3;
  return 0;
}
