#include "cry.h"
#include <time.h>
#include <iostream>
/*################################
  辅助函数
################################*/

/*
printinv: 打印非法
return: 返回值
*/
u8_t runcrypt::printinv(const u8_t ret)
{
  std::cout << "Invalid values.\r\n";
  return ret;
}
/*
printtime: 打印时间
totalTime: 总时间
threads_num: 线程数
*/
void runcrypt::printtime(clock_t totalTime, u8_t threads_num)
{
  std::cout << "Time: " << totalTime / ((double)(CLOCKS_PER_SEC * threads_num))
            << "s / " << totalTime / ((double)CLOCKS_PER_SEC) << "s\r\n";
}
/*
printenc: 打印加密结果
*/
void runcrypt::printenc() { std::cout << "Encrypt over! \r\n"; }
/*
printres: 打印解密结果
res: 解密结果
*/
void runcrypt::printres(int res)
{
  if (res <= 0)
    std::cout << "Verify pass!\r\n";
  else if (res == 1)
    std::cout << "File too short.\r\n";
  else if (res == 2)
    std::cout << "Wrong key or File not complete.\r\n";
  else if (res == 3)
    std::cout << "File not complete.\r\n";
  else if (res == 4)
    std::cout << "Wrong magic number.\r\n";
  else
    std::cout << "Unknown res number: " << res << ".\r\n";
}
/*
over:关闭文件并释放空间
*/
void runcrypt::over()
{
  if (fp != NULL)
    fclose(fp);
  if (out != NULL)
    fclose(out);
}
/*
hashfile:计算文件的HMAC
*/
void runcrypt::hashfile()
{
  u8_t hash[20];
  fseek(out, 28, SEEK_SET);
  hmachandle.gethmac(key, out, hash);
  fseek(out, 8, SEEK_SET);
  fwrite(hash, 1, 20, out);
}
/*
enc:将文件加密
r_buf:随机缓冲数组
*/
void runcrypt::enc(const u8_t *r_buf)
{
  header.getIV(r_buf, iv);
  cm.load_iv(iv);
  header.getFileHeader(iv);
  cm.run_multicry();
  hashfile();
}
/*
dec:将文件解密
return:若成功解密则返回0,否则返回非零值
*/
u8_t runcrypt::dec()
{
  state = verify();
  if (state != 0)
    return state;
  header.getIV(fp, iv);
  dm.load_iv(iv);
  fseek(fp, 28 + (20 * thread_num), SEEK_SET);
  dm.run_multicry();
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
  fseek(fp, 28, SEEK_SET);
  if (!hmachandle.cmphmac(key, fp, hash))
    return 2;
  else
    return 0;
}

/*################################
  接口函数
################################*/
runcrypt::runcrypt(u8_t *data) : fp(GET_VAL(data, fp)), out(GET_VAL(data, out)), key(GET_VAL(data, key)), thread_num(THREAD_NUM),
                                 mode(GET_VAL(data, mode)), r_buf(GET_VAL(data, r_buf)), no_echo(GET_VAL(data, no_echo)), header(GET_VAL(data, fp), GET_VAL(data, out), GET_VAL(data, key), THREAD_NUM), hmachandle(0),
                                 cm(GET_VAL(data, fp), GET_VAL(data, out), GET_VAL(data, key), iv, GET_VAL(data, ctype), THREAD_NUM, GET_VAL(data, no_echo)),
                                 dm(GET_VAL(data, fp), GET_VAL(data, out), GET_VAL(data, key), iv, GET_VAL(data, ctype), THREAD_NUM, GET_VAL(data, no_echo)){};
/*
exec_val:根据传入的参数包执行相应操作
vals:传入的参数包
return:返回是否成功执行
*/
bool runcrypt::exec_val()
{
  int res = 0;
  clock_t cl1 = clock();
  if (fp == NULL)
    return printinv(0);
  if (mode == 'e' || mode == 'E')
  {
    enc(r_buf); // 运行加密
    if (!no_echo)
      printenc(); // 打印结果
  }
  else if (mode == 'd' || mode == 'D')
  {
    res = dec(); // 运行解密
    if (!no_echo)
      printres(res); // 打印结果
  }
  else if (mode == 'v')
  {
    res = verify(); // 运行验证
    if (!no_echo)
      printres(res); // 打印结果
  }
  clock_t cl2 = clock();
  if (!no_echo)
    printtime(cl2 - cl1, thread_num); // 打印时间
  over();                             // 关闭文件
  return res == 0;
}