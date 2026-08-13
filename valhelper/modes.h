#ifndef VMODES
#define VMODES

/*
共享类型枚举(单源):显示类名称表、内核工厂 switch、Settings 校验均引用本处,
从源头消除"显示类与内核工厂类型列表"的重复,计数无法漂移。
*/

/*
CryptMode:加密模式(0=ECB..4=OFB)
CM_COUNT:模式数量哨兵
*/
enum CryptMode : unsigned char
{
  CM_ECB = 0,
  CM_CBC,
  CM_CTR,
  CM_CFB,
  CM_OFB,
  CM_COUNT
};

/*
HashType:哈希类型(0=sha1,1=md5,2=sha256)
HT_COUNT:类型数量哨兵
*/
enum HashType : unsigned char
{
  HT_SHA1 = 0,
  HT_MD5,
  HT_SHA256,
  HT_COUNT
};

constexpr int kCryptModeCount = (int)CM_COUNT;
constexpr int kHashModeCount = (int)HT_COUNT;

#endif
