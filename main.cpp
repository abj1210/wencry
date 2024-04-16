#include "config.h"
#include "cry.h"
#include "getval.h"
#include <iostream>
/*
version:获取版本信息
*/
void version() {
  std::cout << "Wencry version: " << PROJECT_VERSION
            << ". Build time: " << V_BUILD_TIME << "\r\n";
}
void help() {
  std::string description = "命令行参数模式的介绍如下\n\n"
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
                    "- `--hmode` + `[mode]` 指示哈希模式:- 0:sha1 - 1:md5 \n"
                    "- `-n`/`--no_echo` 此选项表示隐藏处理信息\n\n"
                    "### 示例\n\n"
                    "- 加密: ./Wencry -e -i ../a.mp4 -m 2 -o ../a.mp4.wenc\n"
                    "- 解密: ./Wencry -d -i ../a.mp4.wenc -m 2 -o ../aa.mp4 -k Z8Zpc1HSuwpzbqr8vvjRg==\n";
  std::cout << description;

}
int main(int argc, char *argv[]) {
  //初始化
  unsigned char *vals = NULL;
  //获取参数
  if (argc == 1)
    vals = get_v_mod1();
  else {
    vals = get_v_opt(argc, argv);
    if(vals == NULL)
      return 1;
    if(((vpak_t *)vals)->mode == 'V'){
      version();
      return 0;
    }
    else if(((vpak_t *)vals)->mode == 'h'){
      help();
      return 0;
    }
  }
  //执行任务
  runcrypt runner(vals);
  bool flag = runner.exec_val();
  return flag ? 0 : -1;
}