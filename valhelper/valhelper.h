#ifndef VHP
#define VHP

#include "display.h"
#include <string.h>
#include <string>
#include <stdio.h>

typedef unsigned char u8_t;
/*
vpak_t:命令行/交互式模式之间传递的参数包
fp:输入文件指针
out:输出文件指针
key:16字节解密密钥(由base64输入解码得到)
r_buf:随机缓冲数组(加密时生成IV用)
size:输入文件大小
mode:任务模式('e'加密/'d'解密/'v'验证/'V'版本/'h'帮助)
ctype:加密模式(0=ECB..4=OFB)
htype:哈希模式(0=sha1,1=md5,2=sha256)
no_echo:是否隐藏处理过程输出
*/
typedef union
{
  struct
  {
    FILE *fp, *out;
    u8_t *key;
    u8_t r_buf[256];
    size_t size;
    char mode, ctype, htype;
    bool no_echo;
  };
  u8_t buf[512];
} vpak_t;

/*
WencryInformation:程序信息与参数校验类
维护加密/哈希模式的名称表,提供模式名/版本/编译时间/帮助文本的查询,
并校验用户输入的 ctype/htype 是否合法。
*/
class WencryInformation{
    std::string description;
    std::string get_typelist(int count, const char *(*name)(u8_t));
public:
    WencryInformation();
    std::string get_ctypelist();
    std::string get_htypelist();
    bool check_ctype(int ctype_num);
    bool check_htype(int htype_num);
    std::string get_cname(int ctype_num);
    std::string get_hname(int htype_num);
    int get_cname_num();
    int get_hname_num();
    std::string get_version();
    std::string get_buildtime();
    std::string get_help();
};

/*
printkey:将16字节密钥转为base64字符串
key:16字节密钥
return:base64编码后的密钥串(24字符)
*/
std::string printkey(u8_t *key);
/*
checkB64Key:校验base64密钥串并解码为16字节
b64key:base64输入串(24字符)
key:解码输出的16字节密钥
return:合法且可解码为16字节返回true,否则false
*/
bool checkB64Key(const u8_t* b64key, u8_t *key);
/*
getRandomKey:生成随机16字节密钥
return:新分配的随机密钥
*/
u8_t *getRandomKey();
/*
getRandomBuffer:填充256字节随机缓冲(用于生成IV)
r_buf:缓冲数组地址
*/
void getRandomBuffer(u8_t *r_buf);
/*
getProcessMode:将模式字符映射为任务编号
mode:模式字符(e/E/d/D/v)
return:0=加密,1=解密,2=验证,其余=-1
*/
int getProcessMode(char mode);
#endif