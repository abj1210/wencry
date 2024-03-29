#include "multi_buffergroup.h"

/*################################
  单缓冲区函数
################################*/
/*
load_files:设定输入输出文件并初始化缓冲区
fin:输入文件地址
fout:输出文件地址
over:加载是否结束
ispadding:是否为填充模式
return:是否成功装载数据
*/
bool iobuffer::load_files(FILE *fin, FILE *fout, bool &over, bool ispadding) {
  this->fin = fin;
  this->fout = fout;
  this->ispadding = ispadding;
  u32_t sum = BUF_SZ << 4;
  u32_t load = fread(b, 1, sum, fin);
  tail = load & 0xf;
  total = load >> 4;
  now = 0;
  if (ispadding && (load != sum) && (!over)) {
    u8_t padding = 16 - tail;
    memset(b[total] + tail, padding, padding);
    over = true;
    total++;
    return true;
  }
  return load != 0;
}
/*
update_buffer:保存缓冲区数据并更新缓冲区
over:加载是否结束
return:重新读入的字节数
*/
u32_t iobuffer::update_buffer(bool &over) {
  u32_t sum = BUF_SZ << 4;
  fwrite(b, 1, sum, fout);
  u32_t load = fread(b, 1, sum, fin);
  tail = load & 0xf;
  total = load >> 4;
  now = 0;
  if (ispadding && (load != sum) && (!over)) {
    u8_t padding = 16 - tail;
    memset(b[total] + tail, padding, padding);
    over = true;
    total++;
    return load + padding;
  }
  return load;
}
/*
final_write:将缓冲区内容保存到文件并关闭缓冲区
*/
void iobuffer::final_write() {
  u8_t padding = ispadding ? 0 : b[now - 1][15];
  fwrite(b, 1, (now << 4) - padding, fout);
}

/*################################
  多缓冲区函数
################################*/
void printload(const u8_t id, const u32_t size) {
  std::cout << "Buffer of thread id " << (const u32_t)id << " loaded " << size
            << "MB data.\r\n";
}
/*
构造函数:初始化缓冲组的数据
size:缓冲区数量
fin:输入文件指针
fout:输出文件指针
ispadding:是否为填充模式
*/
buffergroup::buffergroup(u32_t size, FILE *fin, FILE *fout, bool ispadding)
    : size(size), turn(0), over(false) {
  buflst = new iobuffer[size];
  for (int i = 0; i < size; ++i)
    if (buflst[i].load_files(fin, fout, over, ispadding))
      printload(i, (iobuffer::BUF_SZ >> 16));
}
/*
update_lst:更新相应相应的缓冲区
id:要更新的缓冲区索引
return:是否成功更新
*/
bool buffergroup::update_lst(const u8_t id) {
  if (buflst[id].fin_empty())
    return false;
  COND_WAIT
  bool flag = (buflst[id].update_buffer(over) != 0);
  if (flag)
    printload(id, (iobuffer::BUF_SZ >> 16));
  COND_RELEASE
  return flag;
}
/*
judge_over:判断相应的缓冲区是否已读取结束并进行相应处理
id:待判断缓冲区的索引
return:文件是否读取完毕
*/
bool buffergroup::judge_over(const u8_t id) {
  if (buflst[id].fin_empty())
    return false;
  bool flag = buflst[id].buffer_over();
  if (flag) {
    COND_WAIT
    buflst[id].final_write();
    COND_RELEASE
  }
  return flag;
}