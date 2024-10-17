#include "getval.h"
#include "config.h"
#include <iostream>
#include <vector>
/*################################
  提示信息
################################*/
static std::vector<std::string>
    ctype = {"ECB", "CBC", "CTR", "CFB", "OFB"},
    htype = {"sha1", "md5", "sha256"};
static std::string description = "命令行参数模式的介绍如下\n\n"
                                 "### 选择模式\n\n"
                                 "- `-e`/`--encode` 为加密模式\n"
                                 "- `-d`/`--decode` 为解密模式\n"
                                 "- `-v`/`--verify` 为验证模式\n"
                                 "- `-V`/`--version` 为查看版本\n"
                                 "- `-h`/`--help` 为查看帮助\n\n"
                                 "### 参数设置\n\n"
                                 "- `-i`/`--input` + `[inputfile]` 指示输入文件路径\n"
                                 "- `-o`/`--output` + `[outputfile]` 指示输出文件路径，缺省为输入文件路径+\".wenc\"后缀\n"
                                 "- `-k`/`--key` + `[key]` 指示ase64编码后的16字节16进制密钥(编码后共24位) ，缺省为随机生成的密钥\n"
                                 "- `--cmode` + `[mode]` 指示加密模式:- 0:电子密码本ECB  - 1:密码块链CBC  - 2:计数器模式CTR  - 3:密文反馈CFB  - 4:输出反馈OFB    \n"
                                 "- `--hmode` + `[mode]` 指示哈希模式:- 0:sha1 - 1:md5 - 2:sha256 \n"
                                 "- `-n`/`--no_echo` 此选项表示隐藏处理信息\n\n"
                                 "### 示例\n\n"
                                 "- 加密: ./Wencry -e -i ../a.mp4 -cmode 2 -o ../a.mp4.wenc\n"
                                 "- 解密: ./Wencry -d -i ../a.mp4.wenc -cmode 2 -o ../aa.mp4 -k Z8Zpc1HSuwpzbqr8vvjRg==\n";
/*################################
  信息获取函数
################################*/
std::string get_typelist(std::vector<std::string> list)
{
  std::string res = "";
  int cnt = 0;
  for (std::vector<std::string>::iterator it = list.begin(); it != list.end(); ++it)
  {
    res += std::to_string(cnt++) + ":" + *it + ", ";
  }
  res.erase(res.end() - 2);
  return res;
}
std::string get_ctypelist()
{
  return get_typelist(ctype);
}
std::string get_htypelist()
{
  return get_typelist(htype);
}
/*
version:获取版本信息
*/
void version()
{
  std::string ver = PROJECT_VERSION;
#ifdef DEBUG_ON
  ver += " Debug";
#endif
  strlog("Wencry version: ", ver);
  strlog("Build time: ", V_BUILD_TIME);
}
std::string verstring()
{
  std::string ver = PROJECT_VERSION;
#ifdef DEBUG_ON
  ver += " Debug";
#endif
  return "Liucan's wencry\r\nKernel version: " + ver + "\r\nBuild time: " + V_BUILD_TIME;
}
/*
help:获取帮助信息
*/
void help()
{
  std::cout << description;
}