
#include "cry.h"
#include "valhelper.h"
#include "getval.h"
#include <iostream>


/*
Wencry程序入口
无参数:进入交互式模式(提示输入文件/密钥/模式)
有参数:解析命令行选项,执行加密/解密/验证任务
异常时返回非0退出码,正常完成返回0
*/
int main(int argc, char *argv[])
{
  unsigned char *vals = NULL;
  // 获取参数

  if (argc == 1)
    vals = getInteractiveArgs();
  else
  {
    vals = getCommandLineArgs(argc, argv);
    WencryInformation wif;
    if (vals == NULL)
      return 1;
    if (((vpak_t *)vals)->mode == 'V')
    {
      logLine("Kernel version", wif.getVersion());
      logLine("Build time", wif.getBuildTime());
      return 0;
    }
    else if (((vpak_t *)vals)->mode == 'h')
    {
      std::cout<<wif.getHelp();
      return 0;
    }
  }
  Settings settings(((vpak_t *)vals)->ctype, ((vpak_t *)vals)->htype, ((vpak_t *)vals)->no_echo);
  // 执行任务
  RunCrypt * runner = createRunCrypt(((vpak_t *)vals)->fp, ((vpak_t *)vals)->out, ((vpak_t *)vals)->key, settings);
  try{
    switch (getProcessMode(((vpak_t *)vals)->mode))
    {
      case 0:
        runner->executeEncrypt(((vpak_t *)vals)->size, ((vpak_t *)vals)->r_buf, ((vpak_t *)vals)->r_len);
        break;
      case 1:
        runner->executeDecrypt(((vpak_t *)vals)->size);
        break;
      case 2:
        runner->executeVerify(((vpak_t *)vals)->size);
        break;
      default:
        destroyRunCrypt(runner);
        return -2;
        break;
    }
  }
  catch(std::string errlog){
    destroyRunCrypt(runner);
    std::cout<<"Error occured:"<<errlog;
    return -1;
  }
  destroyRunCrypt(runner);
  return 0;
}