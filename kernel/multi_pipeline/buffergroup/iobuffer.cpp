#include "multi_buffergroup.h"

/*################################
  单缓冲区函数
################################*/

/*
iobuffer:构造函数,初始化块计数与流水线状态(EMPTY)
*/
iobuffer::iobuffer() : total(0), now(0), tail(0), isfinal(false), state(EMPTY), seq(0), idle_ts(0) {};
/*
get_entry:获取当前缓冲区单元表项
return:返回的表项地址
*/
u8_t *iobuffer::get_entry() { return (now < total) ? b[now++] : NULL; };
/*
get_data:获取缓冲区数据起始地址
return:数据起始地址
*/
u8_t *iobuffer::get_data() { return &b[0][0]; };
/*
data_len:缓冲区实际数据字节数(密文/明文长度,末块含填充)
return:字节数
*/
u32_t iobuffer::data_len() const { return total << 4; };

/*
load_buffer:更新缓冲区
fin:输入文件
ispadding:是否填充
return:返回装载状态
*/
loadstate_t iobuffer::load_buffer(FILE *fin, bool ispadding)
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
export_buffer:将缓冲区内容保存到文件
fout:输出文件
ispadding:是否填充
return:写出的字节数
*/
u32_t iobuffer::export_buffer(FILE *fout, bool ispadding)
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