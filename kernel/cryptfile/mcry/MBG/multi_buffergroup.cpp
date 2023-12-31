#include "multi_buffergroup.h"
#include <iostream>
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