#include "cry.h"
#include <chrono>
#include <iostream>
using namespace std;
using namespace chrono;
/*################################
  辅助函数
################################*/
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
  multicry_master *cm = crym.get_multicry_master('e');
  header.getIV(r_buf, iv);
  cm->load_iv(iv);
  header.getFileHeader(iv);
  cm->run_multicry();
  hmachandle.writeFileHmac(pakout->out, pakout->key, FILE_IV_MARK, FILE_HMAC_MARK);
  delete cm;
}
/*
dec:将文件解密
return:若成功解密则返回0,否则返回非零值
*/
u8_t runcrypt::dec()
{
  u8_t state = verify();
  if (state != 0)
    return state;
  header.getIV(pakout->fp, iv);
  multicry_master *dm = crym.get_multicry_master('d');
  dm->load_iv(iv);
  fseek(pakout->fp, FILE_TEXT_MARK(threads_num), SEEK_SET);
  dm->run_multicry();
  delete dm;
  return 0;
}
/*
verify:验证密钥和文件
return:若为0则检查通过,否则检查不通过
*/
u8_t runcrypt::verify()
{
  if (!header.checkMn())
    return 4;
  if (!header.checkType())
    return 3;
  u8_t *hash = header.getHmac(hmachandle.get_length());
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
runcrypt::runcrypt(u8_t *data, u8_t threads_num) : threads_num(threads_num),
                                                   header(GET_VAL(data, fp), GET_VAL(data, out), GET_VAL(data, key), GET_VAL(data, ctype), GET_VAL(data, htype), threads_num),
                                                   hmachandle(GET_VAL(data, htype)), resultprint(threads_num, GET_VAL(data, no_echo)),
                                                   crym(GET_VAL(data, fp), GET_VAL(data, out), GET_VAL(data, key), iv, GET_VAL(data, ctype), threads_num, GET_VAL(data, no_echo))
{
  pakout = new pakout_t;
  memcpy(pakout->buf, GET_VAL(data, buf), 512);
  memset(iv, 0, sizeof(iv));
};
/*
exec_val:根据传入的参数包执行相应操作
vals:传入的参数包
return:返回是否成功执行
*/
bool runcrypt::exec_val()
{
  int res = 0;
  auto start = system_clock::now();
  if (pakout->fp == NULL)
    return resultprint.printinv(0);
  if (pakout->mode == 'e' || pakout->mode == 'E')
  {
    enc(pakout->r_buf);     // 运行加密
    resultprint.printenc(); // 打印结果
  }
  else if (pakout->mode == 'd' || pakout->mode == 'D')
  {
    res = dec();               // 运行解密
    resultprint.printres(res); // 打印结果
  }
  else if (pakout->mode == 'v')
  {
    res = verify();            // 运行验证
    resultprint.printres(res); // 打印结果
  }
  else
  {
    return resultprint.printinv(6);
  }
  auto end = system_clock::now();
  auto duration = duration_cast<microseconds>(end - start);
  resultprint.printtime(duration); // 打印时间
  over();                          // 关闭文件
  return res == 0;
}