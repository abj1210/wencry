#include "multi_buffergroup.h"
#include "util.h"

#include <iostream>
/*
构造函数:初始化缓冲组的数据
size:缓冲区数量
fin:输入文件指针
fout:输出文件指针
*/
buffergroup::buffergroup(unsigned int size, FILE *fin, FILE *fout)
    : size(size) {
  buflst = new iobuffer[size];
  fileaccess = new std::mutex[size];
  for (int i = 0; i < size; i++) {
    if (buflst[i].load_files(fin, fout))
      std::cout << "Buffer of thread id " << i << " loaded "
                << (iobuffer::BUF_SZ >> 16) << "MB data.\r\n";
    if (i != 0)
      fileaccess[i].lock();
  }
}
/*
析构函数:释放缓冲区组
*/
buffergroup::~buffergroup() {
  delete[] buflst;
  delete[] fileaccess;
}
/*
require_buffer_entry:获取相应的缓冲区表项
id:缓冲区索引
return:相应缓冲区的待处理表项,若已处理完毕则输出NULL
*/
unsigned char *buffergroup::require_buffer_entry(unsigned int id) {
  return buflst[id].get_entry();
}
/*
update_lst:更新相应相应的缓冲区
id:要更新的缓冲区索引
return:是否成功更新
*/
bool buffergroup::update_lst(unsigned int id) {
  if (buflst[id].fin_empty())
    return false;
  fileaccess[id].lock();
  bool flag = (buflst[id].update_buffer() != 0);
  if (flag)
    std::cout << "Buffer of thread id " << id << " loaded "
              << (iobuffer::BUF_SZ >> 16) << "MB data.\r\n";
  fileaccess[(id + 1) % size].unlock();
  return flag;
}
/*
judge_over:判断相应的缓冲区是否已读取结束
id:待判断缓冲区的索引
tail:最后一表项要写入的字节数
return:最后一表项写入的字节数,若该缓冲区未结束则返回0;
*/
int buffergroup::judge_over(unsigned int id, unsigned int tail) {
  if (buflst[id].fin_empty())
    return 0;
  if (buflst[id].buffer_over()) {
    fileaccess[id].lock();
    int sum = buflst[id].final_write(tail);
    fileaccess[(id + 1) % size].unlock();
    return sum;
  } else
    return 0;
}