#include "valhelper.h"
#include "config.h"


/*
构造函数:初始化模式名称表与帮助文本
ctype:五种AES加密模式名称
htype:三种哈希模式名称
*/
WencryInformation::WencryInformation():
  ctype({"ECB", "CBC", "CTR", "CFB", "OFB"}),
  htype({"sha1", "md5", "sha256"})
{
  description = "命令行参数模式的介绍如下\n\n"
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
                                 "- 加密: ./Wencry -e -i ../a.mp4 --cmode 2 -o ../a.mp4.wenc\n"
                                 "- 解密: ./Wencry -d -i ../a.mp4.wenc --cmode 2 -o ../aa.mp4 -k Z8Zpc1HSuwpzbqr8vvjRg==\n";

}
/*
get_typelist:将名称表格式化为"编号:名称, "形式的字符串
list:名称表
return:格式化后的类型列表
*/
std::string WencryInformation::get_typelist(std::vector<std::string> list)
{
  std::string res = "";
  int cnt = 0;
  for (std::vector<std::string>::iterator it = list.begin(); it != list.end(); ++it)
    res += std::to_string(cnt++) + ":" + *it + ", ";
  res.erase(res.end() - 2);
  return res;
}
/*
get_ctypelist:获取加密模式列表
return:加密模式列表字符串
*/
std::string WencryInformation::get_ctypelist()
{
  return get_typelist(ctype);
}
/*
get_htypelist:获取哈希模式列表
return:哈希模式列表字符串
*/
std::string WencryInformation::get_htypelist()
{
  return get_typelist(htype);
}
/*
check_ctype:校验加密模式编号是否合法
ctype_num:待校验的编号
return:合法返回true,否则false
*/
bool WencryInformation::check_ctype(int ctype_num)
{
  return ctype_num >= 0 && (size_t)ctype_num < ctype.size();
}
/*
check_htype:校验哈希模式编号是否合法
htype_num:待校验的编号
return:合法返回true,否则false
*/
bool WencryInformation::check_htype(int htype_num)
{
  return htype_num >= 0 && (size_t)htype_num < htype.size();
}
/*
get_cname:获取加密模式名称
ctype_num:模式编号
return:模式名称(非法编号返回"unknown")
*/
std::string WencryInformation::get_cname(int ctype_num)
{
  if (check_ctype(ctype_num))
    return ctype[ctype_num];
  else
    return "unknown";
}
/*
get_hname:获取哈希模式名称
htype_num:模式编号
return:模式名称(非法编号返回"unknown")
*/
std::string WencryInformation::get_hname(int htype_num)
{
  if (check_htype(htype_num))
    return htype[htype_num];
  else
    return "unknown";
}
/*
get_cname_num:获取加密模式数量
return:加密模式数量
*/
int WencryInformation::get_cname_num(){
  return ctype.size();
}
/*
get_hname_num:获取哈希模式数量
return:哈希模式数量
*/
int WencryInformation::get_hname_num(){
  return htype.size();
}
/*
get_version:获取内核版本号(Debug编译附加" Debug"后缀)
return:版本号字符串
*/
std::string WencryInformation::get_version(){
  std::string ver = PROJECT_VERSION;
#ifdef DEBUG_ON
  ver += " Debug";
#endif
  return ver;
}
/*
get_buildtime:获取编译时间
return:编译时间字符串
*/
std::string WencryInformation::get_buildtime(){
  return V_BUILD_TIME;
}
/*
get_help:获取命令行帮助文本
return:帮助文本字符串
*/
std::string WencryInformation::get_help()
{
  return description;
}