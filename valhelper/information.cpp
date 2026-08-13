#include "valhelper.h"
#include "config.h"


/*
构造函数:初始化帮助文本(模式名称由 display.h 的单源表提供)
*/
WencryInformation::WencryInformation()
{
  description = "用法: wencry [模式] [选项]\n\n"
                                 "模式(必选其一):\n"
                                 "  -e, --encode     加密\n"
                                 "  -d, --decode     解密\n"
                                 "  -v, --verify     验证\n"
                                 "  -V, --version    查看版本\n"
                                 "  -h, --help       查看帮助\n\n"
                                 "选项:\n"
                                 "  -i, --input <文件>     输入文件路径\n"
                                 "  -o, --output <文件>    输出文件路径(缺省为输入文件路径 + \".wenc\")\n"
                                 "  -k, --key <密钥>       16字节密钥的 base64 编码(共24字符),缺省随机生成\n"
                                 "  --cmode <模式>         加密模式: 0:ECB  1:CBC  2:CTR  3:CFB  4:OFB\n"
                                 "  --hmode <模式>         哈希模式: 0:sha1  1:md5  2:sha256\n"
                                 "  -n, --no_echo          隐藏处理过程信息\n\n"
                                 "示例:\n"
                                 "  加密: wencry -e -i a.mp4 --cmode 2 -o a.mp4.wenc\n"
                                 "  解密: wencry -d -i a.mp4.wenc --cmode 2 -o a.mp4 -k <密钥>\n";

}
/*
get_typelist:按单源名称表格式化"编号:名称, "形式的字符串
count:模式数量
name:名称查询函数
return:格式化后的类型列表
*/
std::string WencryInformation::get_typelist(int count, const char *(*name)(u8_t))
{
  std::string res = "";
  for (int i = 0; i < count; ++i)
  {
    if (i)
      res += ", ";
    res += std::to_string(i) + ":" + name((u8_t)i);
  }
  return res;
}
/*
get_ctypelist:获取加密模式列表
return:加密模式列表字符串
*/
std::string WencryInformation::get_ctypelist()
{
  return get_typelist(kCryptModeCount, crypt_mode_name);
}
/*
get_htypelist:获取哈希模式列表
return:哈希模式列表字符串
*/
std::string WencryInformation::get_htypelist()
{
  return get_typelist(kHashModeCount, hash_mode_name);
}
/*
check_ctype:校验加密模式编号是否合法
ctype_num:待校验的编号
return:合法返回true,否则false
*/
bool WencryInformation::check_ctype(int ctype_num)
{
  return ctype_num >= 0 && ctype_num < kCryptModeCount;
}
/*
check_htype:校验哈希模式编号是否合法
htype_num:待校验的编号
return:合法返回true,否则false
*/
bool WencryInformation::check_htype(int htype_num)
{
  return htype_num >= 0 && htype_num < kHashModeCount;
}
/*
get_cname:获取加密模式名称
ctype_num:模式编号
return:模式名称(非法编号返回"unknown")
*/
std::string WencryInformation::get_cname(int ctype_num)
{
  return check_ctype(ctype_num) ? crypt_mode_name((u8_t)ctype_num) : "unknown";
}
/*
get_hname:获取哈希模式名称
htype_num:模式编号
return:模式名称(非法编号返回"unknown")
*/
std::string WencryInformation::get_hname(int htype_num)
{
  return check_htype(htype_num) ? hash_mode_name((u8_t)htype_num) : "unknown";
}
/*
get_cname_num:获取加密模式数量
return:加密模式数量
*/
int WencryInformation::get_cname_num(){
  return kCryptModeCount;
}
/*
get_hname_num:获取哈希模式数量
return:哈希模式数量
*/
int WencryInformation::get_hname_num(){
  return kHashModeCount;
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