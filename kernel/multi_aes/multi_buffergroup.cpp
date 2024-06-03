#include "multi_buffergroup.h"
#include <assert.h>
#include <iomanip>
#include <math.h>
/*
update_buffer:保存缓冲区数据并更新缓冲区
over:加载是否结束
return:重新读入的字节数
*/
u32_t iobuffer::update_buffer(bool write, bool &over)
{
  u32_t sum = BUF_SZ << 4;
  if (write)
    fwrite(b, 1, sum, fout);
  u32_t load = fread(b, 1, sum, fin);
  bool readover = feof(fin);
  tail = load & 0xf;
  total = load >> 4;
  now = 0;
  if (ispadding && (load != sum) && (!over))
  {
    u8_t padding = 16 - tail;
    memset(b[total] + tail, padding, padding);
    isfinal = true;
    over = true;
    total++;;
    return load + padding;
  }
  if((!ispadding) && readover && (!over)){
    isfinal = true;
    over = true;
  }
  
  return load;
}
/*
final_write:将缓冲区内容保存到文件并关闭缓冲区
*/
void iobuffer::final_write()
{
  u8_t padding = ispadding ? 0 : b[now - 1][15];
  fwrite(b, 1, (now << 4) - padding, fout);
}

/*################################
  多缓冲区函数
################################*/
/*
printload:打印装载情况
id:装载数据的线程
size:装载大小
*/
void buffergroup::printload(const u8_t id, const size_t size)
{
  now_size += size;
  double percentage = 100.0*((double)now_size / (double)(total_size));
  std::cout << "Tid " << (const u32_t)id << " loaded ";
  const int barWidth = 50; // 进度条的总宽度
  std::cout << "[";
  int pos = round(barWidth * percentage / 100.0);
  for (int i = 0; i < barWidth; ++i) {
      if (i < pos) std::cout << "=";
      else if (i == pos) std::cout << ">";
      else std::cout << " ";
  }
  std::cout << "] " <<std::setw(12)<< std::fixed << std::setprecision(2)<< percentage << " %\r";
  std::cout.flush();
}
/*
构造函数:初始化缓冲组的数据
size:缓冲区数量
no_echo:是否屏蔽输出
*/
buffergroup::buffergroup(u32_t size, bool no_echo)
    : buflst(NULL), size(size), turn(0), over(false), no_echo(no_echo)
{
}

buffergroup *buffergroup::instance = NULL;
std::mutex buffergroup::mtx;

buffergroup *buffergroup::get_instance(u32_t size, bool no_echo)
{
  if (instance == NULL)
  {
    std::lock_guard<std::mutex> lock(mtx);
    if (instance == NULL)
    {
      instance = new buffergroup(size, no_echo);
    }
  }
  return instance;
};

void buffergroup::del_instance()
{
  if (instance != NULL)
  {
    std::lock_guard<std::mutex> lock(mtx);
    if (instance != NULL)
    {
      delete instance;
      instance = NULL;
    }
  }
};

/*
load_files:加载文件到缓冲区
fin:输入文件地址
fout:输出文件地址
ispadding:是否为填充模式
*/
void buffergroup::load_files(FILE *fin, FILE *fout, bool ispadding, u64_t fsize)
{
  buflst = new iobuffer[size];
  cv = new std::condition_variable[size];
  now_size = 0;
  total_size = size == 0 ? 1 : fsize;
  for (int i = 0; i < size; ++i)
  {
    buflst[i].init(fin, fout, ispadding);
    size_t loadsize = buflst[i].update_buffer(false, over);
    if (loadsize != 0)
      if (!no_echo)
        printload(i, loadsize);
  }
}
/*
update_lst:更新相应相应的缓冲区
id:要更新的缓冲区索引
return:是否成功更新
*/
bool buffergroup::update_lst(const u8_t id)
{
  if (buflst[id].fin_empty())
    return false;
  COND_WAIT
  size_t loadsize = buflst[id].update_buffer(true, over);
  if ((loadsize != 0) && (!no_echo))
    printload(id, loadsize);
  COND_RELEASE
  return (loadsize != 0);
}
/*
judge_over:判断相应的缓冲区是否已读取结束并进行相应处理
id:待判断缓冲区的索引
return:文件是否读取完毕
*/
bool buffergroup::judge_over(const u8_t id)
{
  if (buflst[id].fin_empty())
    return false;
  bool flag = buflst[id].buffer_over();
  if (flag)
  {
    COND_WAIT
    buflst[id].final_write();
    if (!no_echo)
      std::cout<<std::endl;
    COND_RELEASE
  }
  return flag;
}