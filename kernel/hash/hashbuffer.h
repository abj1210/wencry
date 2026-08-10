#ifndef SBF
#define SBF
#include <stdio.h>
#include <functional>
#include <string>
typedef unsigned char u8_t;
typedef unsigned int u32_t;
/*
buffer64:哈希输入缓冲抽象接口
为 Hashmaster::getFileHash 提供逐64字节块读取的数据源。
*/
class buffer64
{
public:
  virtual ~buffer64() {};
  virtual u32_t read_buffer64(u8_t *block, const std::function<void(std::string, size_t)> &printload) = 0;
};
/*
filebuffer64:基于FILE*的64字节块缓冲(哈希大文件用)
b:数据缓冲区(每行64字节)
extra_entry:额外拼接块(HMAC的ipad块先于此缓冲进入哈希流)
has_extra:是否还有未消费的额外块
total:缓冲区被填满的单元数量
now:将要被读写的单元索引
tail:末尾未填满单元中的有效字节数
fp:输入文件
HBUF_SZ=0x80000 -> 单次装载 32MB,耗尽后自动续读。
*/
class filebuffer64 : public buffer64
{
  static const u32_t HBUF_SZ = 0x80000;
  u8_t b[HBUF_SZ][0x40];
  u8_t extra_entry[0x40];
  bool has_extra;
  u32_t total, now;
  u8_t tail;
  FILE *fp;

public:
  filebuffer64(FILE *fp, const std::function<void(std::string, size_t)> &printload = [](std::string, size_t) -> void {}, u8_t *block = NULL);
  u32_t read_buffer64(u8_t *block, const std::function<void(std::string, size_t)> &printload = [](std::string, size_t) -> void {});
};
#endif
