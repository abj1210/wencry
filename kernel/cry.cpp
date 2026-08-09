#include "cry.h"
#include <chrono>
#include <iostream>
#include <functional>
using namespace std;
using namespace chrono;

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
  if (!cmode)
    fseek(fin, FILE_TEXT_MARK(threads_num), SEEK_SET);
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
  if (!header.checkMn())
    return 4;
  header.checkType();
  resultprint->printctype(header.getctype());
  resultprint->printhtype(header.gethtype());
  u8_t *hash = header.getHmac(64);
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
runcrypt::runcrypt::runcrypt(FILE *fin, FILE *out, u8_t *key, Settings settings, u8_t threads_num)
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
execute_encrypt:加密执行过程
fsize:文件大小
r_buf:随机缓冲数组
*/
bool runcrypt::execute_encrypt(size_t fsize, u8_t *r_buf)
{
  if (fin == NULL)
    return resultprint->printinv(0);
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
  TIMER_START(Hashing_Time)
  resultprint->printtask("Calculating hmac");
  hmachandle.final_hash();
  hmachandle.write_hmac(out, FILE_HMAC_MARK);
  resultprint->resetPercentage();
  TIMER_END(Hashing_Time)
  // 释放空间
  resultprint->printtask("Releasing allocated memory");
  release(iv, mode);
  resultprint->printenc(); // 打印结果
  over();                  // 关闭文件
  TIMER_END(Total_Time);   // 打印时间
  return true;
}
/*
execute_decrypt:解密执行过程
fsize:文件大小
*/
bool runcrypt::execute_decrypt(size_t fsize)
{
  if (fin == NULL)
    return resultprint->printinv(0);
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
  return res == 0;
}
/*
execute_verify:验证执行过程
fsize:文件大小
*/
bool runcrypt::execute_verify(size_t fsize)
{
  if (fin == NULL)
    return resultprint->printinv(0);
  TIMER_START(Total_Time);
  // 验证文件
  TIMER_START(Verify_Time);
  int res = verify(fsize);
  resultprint->resetPercentage();
  TIMER_END(Verify_Time);
  resultprint->printresv(res); // 打印结果
  over();                      // 关闭文件
  TIMER_END(Total_Time);       // 打印时间
  return res == 0;
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
