#include "cry.h"
#include <time.h>
#include <iostream>
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
hashfile:计算文件的HMAC
*/
void runcrypt::hashfile()
{
  u8_t hash[20];
  fseek(pakout->out, FILE_IV_MARK, SEEK_SET);
  hmachandle.gethmac(pakout->key, pakout->out, hash);
  fseek(pakout->out, FILE_HMAC_MARK, SEEK_SET);
  fwrite(hash, 1, 20, pakout->out);
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
  hashfile();
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
  u8_t *hash = header.getHmac();
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
                                 header(GET_VAL(data, fp), GET_VAL(data, out), GET_VAL(data, key), threads_num), hmachandle(0),
                                 resultprint(threads_num, GET_VAL(data, no_echo)),
                                 crym(GET_VAL(data, fp), GET_VAL(data, out), GET_VAL(data, key), iv, GET_VAL(data, ctype), threads_num, GET_VAL(data, no_echo))
                                 {
                                   pakout = new pakout_t;
                                   memcpy(pakout->buf,  GET_VAL(data, buf), 512);
                                 };
/*
exec_val:根据传入的参数包执行相应操作
vals:传入的参数包
return:返回是否成功执行
*/
bool runcrypt::exec_val()
{
  int res = 0;
  clock_t cl1 = clock();
  if (pakout->fp == NULL)
    return resultprint.printinv(0);
  if (pakout->mode == 'e' || pakout->mode == 'E')
  {
    enc(pakout->r_buf); // 运行加密
    resultprint.printenc(); // 打印结果
  }
  else if (pakout->mode == 'd' || pakout->mode == 'D')
  {
    res = dec(); // 运行解密
    resultprint.printres(res); // 打印结果
  }
  else if (pakout->mode == 'v')
  {
    res = verify(); // 运行验证
    resultprint.printres(res); // 打印结果
  }
  clock_t cl2 = clock();
  resultprint.printtime(cl2 - cl1); // 打印时间
  over();                             // 关闭文件
  return res == 0;
}