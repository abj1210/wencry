#include "multi_buffergroup.h"

/*################################
  单缓冲区函数
################################*/

/*
IoBuffer:构造函数,初始化块计数与流水线状态(EMPTY)
*/
IoBuffer::IoBuffer()
    : total(0), now(0), seq(0),
      id(s_next_id.fetch_add(1, std::memory_order_relaxed))
{
  SCHED_LOG(g_sched_role, "BUF_NEW", id, -1, "", -1, -1, -1);
};
/*
~IoBuffer:析构,记录缓冲区销毁事件
*/
IoBuffer::~IoBuffer()
{
  SCHED_LOG(g_sched_role, "BUF_DELETE", id, seq, "", -1, -1, -1);
};
/*
getEntry:获取当前缓冲区单元表项
return:返回的表项地址
*/
u8_t *IoBuffer::getEntry() { return (now < total) ? b[now++] : NULL; };
/*
getData:获取缓冲区数据起始地址
return:数据起始地址
*/
u8_t *IoBuffer::getData() { return &b[0][0]; };
/*
dataLen:缓冲区实际数据字节数(密文/明文长度,末块含填充)
return:字节数
*/
u32_t IoBuffer::dataLen() const { return total << 4; };

u64_t IoBuffer::get_seq() const {return seq;};

void IoBuffer::set_seq(u64_t seq){this->seq = seq;};

/*
loadBuffer:从输入文件装载一个缓冲区
fin:输入文件
ispadding:是否需要填充(加密为 true,末块按 PKCS7 补齐到 16 字节边界)
return:FULL=装满整块(是否还有后续数据由下一次装载判定)
        FINAL=最后一块(数据已装入,加密时已补齐填充)
        NODATA=确实没有数据(空文件/已到末尾)
*/
loadstate_t IoBuffer::loadBuffer(FILE *fin, bool ispadding)
{
  size_t load = fread(b, 1, sum, fin);
  total = (u32_t)(load >> 4);
  u32_t tail = (u32_t)(load & 0xf);   // 末块未被填满的字节数(仅本函数使用的临时量)
  now = 0;
  if (load == sum)
    return FULL;
  if (load == 0)
  {
    if (!ispadding)
      return NODATA;
    total = 1;                 // 空文件也要产生一个全填充块(PKCS7)
    memset(b[0], 0x10, 0x10);
    return FINAL;
  }
  if (ispadding)               // 末块不足一整块:补齐 PKCS7 填充
  {
    u8_t padding = (u8_t)(0x10 - tail);
    memset(b[total++] + tail, padding, padding);
  }
  return FINAL;
}
/*
exportBuffer:将缓冲区内容保存到文件
fout:输出文件
isfinal:是否为最后一块(由 BufferGroup::getFinalBlock 判定)
ispadding:写入侧是否为加密(加密输出含 PKCS7 填充,不需要截断)
return:写出的字节数
*/
u32_t IoBuffer::exportBuffer(FILE *fout, bool isfinal, bool ispadding)
{
  if (total == 0)
    return 0;
  u32_t n = total << 4;
  if (isfinal && !ispadding)   // 解密末块:按 PKCS7 填充字节长度截断
  {
    u8_t padding = b[total - 1][0xf];
    if ((u32_t)padding > n)
      padding = (u8_t)n;
    n -= padding;
  }
  fwrite(b, 1, n, fout);
  return n;
}
