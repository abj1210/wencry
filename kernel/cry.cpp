#include "cry.h"
#include <chrono>
#include <iostream>
using namespace std;
using namespace chrono;
#define TIMER_START(timer) auto t_##timer = resultprint->createTimer(#timer);
#define TIMER_END(timer) resultprint->printTimer(t_##timer);
/*################################
  辅助函数
################################*/
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
  header.getIV(pakout->fp, iv);
  return iv;
}
/*
prepare_AESE:准备缓冲区和aes加密器
iv:初始向量
return:加密器地址组
*/
Aesmode **runcrypt::prepare_AESE(u8_t *iv)
{
  buffergroup *iobuffer = buffergroup::get_instance();
  iobuffer->set_buffergroup(threads_num, GET_VAL(pakout, no_echo), GET_VAL(pakout, fp), GET_VAL(pakout, out), true, GET_VAL(pakout, size));
  Aesmode **mode = new Aesmode *[threads_num];
  aesfactory.loadiv(iv);
  for (int i = 0; i < threads_num; i++)
    mode[i] = aesfactory.createCryMaster(true, GET_VAL(pakout, ctype));
  return mode;
}
/*
prepare_AESD:准备缓冲区和aes解密器
iv:初始向量
return:加密器地址组
*/
Aesmode **runcrypt::prepare_AESD(u8_t *iv)
{
  aesfactory.loadiv(iv);
  fseek(pakout->fp, FILE_TEXT_MARK(threads_num), SEEK_SET);
  buffergroup *iobuffer = buffergroup::get_instance();
  iobuffer->set_buffergroup(threads_num, GET_VAL(pakout, no_echo), GET_VAL(pakout, fp), GET_VAL(pakout, out), false, GET_VAL(pakout, size));
  Aesmode **mode = new Aesmode *[threads_num];
  for (int i = 0; i < threads_num; i++)
    mode[i] = aesfactory.createCryMaster(false, GET_VAL(pakout, ctype));
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
  {
    buffergroup::del_instance();
    delete mode[i];
  }
  delete[] mode;
}
/*
over:关闭文件并释放空间
*/
void runcrypt::over()
{
  if (pakout->fp != NULL)
    fclose(pakout->fp);
  if (pakout->out != NULL)
    fclose(pakout->out);
}
/*
enc:将文件加密
r_buf:随机缓冲数组
*/
void runcrypt::enc(const u8_t *r_buf)
{
  // 准备初始化
  resultprint->printtask("Preparing encrypt");
  u8_t *iv = prepare_IV(r_buf);
  Aesmode **mode = prepare_AESE(iv);
  // 运行加密
  TIMER_START(AES_Encryption_Time)
  resultprint->printtask("Encrypting");
  crym.run_multicry(mode);
  TIMER_END(AES_Encryption_Time)
  // 写入hamc
  TIMER_START(Hashing_Time)
  resultprint->printtask("Calculating hmac");
  hmachandle.writeFileHmac(pakout->out, pakout->key, FILE_IV_MARK, FILE_HMAC_MARK);
  TIMER_END(Hashing_Time)
  // 释放空间
  resultprint->printtask("Releasing allocated memory");
  release(iv, mode);
}
/*
dec:将文件解密
return:若成功解密则返回0,否则返回非零值
*/
u8_t runcrypt::dec()
{
  // 验证文件
  TIMER_START(Verify_Time);
  u8_t state = verify();
  TIMER_END(Verify_Time);
  if (state != 0)
    return state;
  // 准备初始化
  resultprint->printtask("Preparing decrypt");
  u8_t *iv = prepare_IV();
  Aesmode **mode = prepare_AESD(iv);
  // 运行解密
  TIMER_START(AES_Decryption_Time)
  resultprint->printtask("Decrypting");
  crym.run_multicry(mode);
  TIMER_END(AES_Decryption_Time)
  // 释放空间
  resultprint->printtask("Releasing allocated memory");
  release(iv, mode);
  return 0;
}
/*
verify:验证密钥和文件
return:若为0则检查通过,否则检查不通过
*/
u8_t runcrypt::verify()
{
  resultprint->printtask("Verifying file");
  if (!header.checkMn())
    return 4;
  if (!header.checkType())
    return 3;
  u8_t *hash = header.getHmac(64);
  if (hash == NULL)
    return 1;
  fseek(pakout->fp, FILE_IV_MARK, SEEK_SET);
  if (!hmachandle.cmphmac(pakout->key, pakout->fp, hash))
    return 2;
  else
    return 0;
}

/*################################
  接口函数
################################*/
runcrypt::runcrypt(u8_t *data, u8_t threads_num) : header(GET_VAL(data, fp), GET_VAL(data, out), GET_VAL(data, key), GET_VAL(data, ctype), GET_VAL(data, htype), threads_num),
                                                   hmachandle(GET_VAL(data, htype)), aesfactory(GET_VAL(data, key)), crym(threads_num), threads_num(threads_num)
{
  if (GET_VAL(data, no_echo))
    resultprint = new NullResPrint;
  else
    resultprint = new ResultPrint;
  pakout = new pakout_t;
  memcpy(pakout->buf, GET_VAL(data, buf), 512);
};
/*
exec_val:根据传入的参数包执行相应操作
vals:传入的参数包
return:返回是否成功执行
*/
bool runcrypt::exec_val()
{
  int res = 0;
  auto t1 = resultprint->createTimer("Total_Time");
  if (pakout->fp == NULL)
    return resultprint->printinv(0);
  if (pakout->mode == 'e' || pakout->mode == 'E')
  {
    enc(pakout->r_buf);      // 运行加密
    resultprint->printenc(); // 打印结果
  }
  else if (pakout->mode == 'd' || pakout->mode == 'D')
  {
    res = dec();                // 运行解密
    resultprint->printres(res); // 打印结果
  }
  else if (pakout->mode == 'v')
  {
    res = verify();             // 运行验证
    resultprint->printres(res); // 打印结果
  }
  else
    return resultprint->printinv(6);
  resultprint->printTimer(t1); // 打印时间
  over();                      // 关闭文件
  return res == 0;
}