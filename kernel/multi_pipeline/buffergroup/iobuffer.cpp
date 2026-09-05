#include "multi_buffergroup.h"

/*################################
  单缓冲区函数
################################*/

/*
IoBuffer:构造函数,初始化块计数与流水线状态(EMPTY)
*/
IoBuffer::IoBuffer()
    : total(0), now(0), tail(0), isfinal(false), claimed(false), seq(0), idle_ts(0),
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

/*
loadBuffer:更新缓冲区
fin:输入文件
ispadding:是否填充
return:返回装载状态
*/
loadstate_t IoBuffer::loadBuffer(FILE *fin, bool ispadding)
{
  u32_t load = fread(b, 1, sum, fin);
  bool readover = feof(fin);
  if (!ispadding && !readover && load == sum)
  {
    int c = fgetc(fin);
    readover = (c == EOF);
    if (!readover)
      fseek(fin, -1, SEEK_CUR);
  }
  tail = load & 0xf;
  total = load >> 4;
  now = 0;
  if (ispadding && (load != sum))
  {
    u8_t padding = 16 - tail;
    memset(b[total++] + tail, padding, padding);
    isfinal = true;
    return FINAL;
  }
  if ((!ispadding) && readover)
  {
    if (load == 0)
      return NODATA;
    isfinal = true;
    return FINAL;
  }
  return load == 0 ? NODATA : FULL;
}
/*
exportBuffer:将缓冲区内容保存到文件
fout:输出文件
ispadding:是否填充
return:写出的字节数
*/
u32_t IoBuffer::exportBuffer(FILE *fout, bool ispadding)
{
  if (now == 0)
    return 0;
  if (isfinal)
  {
    u8_t padding = ispadding ? 0 : b[now - 1][15];
    if (padding > (now << 4))
      padding = (u8_t)(now << 4);
    u32_t n = (now << 4) - padding;
    fwrite(b, 1, n, fout);
    return n;
  }
  fwrite(b, 1, sum, fout);
  return sum;
}
