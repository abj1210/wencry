
#include "cry.h"
#include "valhelper.h"
#include "getval.h"
#include <iostream>
#include <time.h>


/*
Wencry程序入口
无参数:进入交互式模式(提示输入文件/密钥/模式)
有参数:解析命令行选项,执行加密/解密/验证任务
异常时返回非0退出码,正常完成返回0
*/
int main(int argc, char *argv[])
{
  // 初始化
  srand(time(NULL));
  unsigned char *vals = NULL;
  // 获取参数

  if (argc == 1)
    vals = get_v_mod1();
  else
  {
    vals = get_v_opt(argc, argv);
    WencryInformation wif;
    if (vals == NULL)
      return 1;
    if (((vpak_t *)vals)->mode == 'V')
    {
      strlog("Kernel version", wif.get_version());
      strlog("Build time", wif.get_buildtime());
      return 0;
    }
    else if (((vpak_t *)vals)->mode == 'h')
    {
      std::cout<<wif.get_help();
      return 0;
    }
  }
  Settings settings(((vpak_t *)vals)->ctype, ((vpak_t *)vals)->htype, ((vpak_t *)vals)->no_echo);
  // 执行任务
  runcrypt runner(((vpak_t *)vals)->fp, ((vpak_t *)vals)->out, ((vpak_t *)vals)->key, settings);
  try{
    switch (getProcessMode(((vpak_t *)vals)->mode))
    {
      case 0:
        runner.execute_encrypt(((vpak_t *)vals)->size, ((vpak_t *)vals)->r_buf);
        break;
      case 1:
        runner.execute_decrypt(((vpak_t *)vals)->size);
        break;
      case 2:
        runner.execute_verify(((vpak_t *)vals)->size);
        break;
      default:
        return -2;
        break;
    }
  }
  catch(std::string errlog){
    std::cout<<"Error occured:"<<errlog;
    return -1;
  }
  return 0;
}