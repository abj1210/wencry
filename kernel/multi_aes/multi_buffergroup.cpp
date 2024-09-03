#include "multi_buffergroup.h"
#include <assert.h>
#include <iomanip>
#include <math.h>

/*################################
  初始化
################################*/

u8_t bufferctrl::live_num = 0;
buffergroup *buffergroup::instance = NULL;
std::mutex buffergroup::mtx;

/*################################
  单缓冲区函数
################################*/
/*
update_buffer:保存缓冲区数据并更新缓冲区
over:加载是否结束
return:重新读入的字节数
*/
u32_t iobuffer::update_buffer(bool write, bool &over)
{
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
    memset(b[total++] + tail, padding, padding);
    isfinal = true;
    over = true;
    return load + padding;
  }
  if ((!ispadding) && readover && (!over))
  {
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
  缓冲区控制函数
################################*/
/*
wait_ready:等待装载就绪
*/
void bufferctrl::wait_ready()
{
  std::unique_lock<std::mutex> locker(lock);
  while (state != READY && state != INV)
    cv.wait(locker);
  locker.unlock();
}
/*
wait_update:等待可以装载
*/
void bufferctrl::wait_update()
{
  std::unique_lock<std::mutex> locker(lock);
  while (state != UPDATING && state != EMPTY)
    cv.wait(locker);
  locker.unlock();
}
/*
set_ready:设置就绪状态
*/
void bufferctrl::set_ready()
{
  std::unique_lock<std::mutex> locker(lock);
  state = READY;
  cv.notify_all();
  locker.unlock();
}
/*
set_update:设置可装载状态
*/
void bufferctrl::set_update()
{
  std::unique_lock<std::mutex> locker(lock);
  if (state == READY)
  {
    state = UPDATING;
    cv.notify_all();
  }
  locker.unlock();
}
/*
设置无效状态
*/
void bufferctrl::set_inv()
{
  std::unique_lock<std::mutex> locker(lock);
  state = INV;
  live_num--;
  cv.notify_all();
  locker.unlock();
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
  double percentage = 100.0 * ((double)now_size / (double)(total_size));
  std::cout << "Tid " << (const u32_t)id << " loaded ";
  const int barWidth = 50; // 进度条的总宽度
  std::cout << "[";
  int pos = round(barWidth * percentage / 100.0);
  for (int i = 0; i < barWidth; ++i)
  {
    if (i < pos)
      std::cout << "=";
    else if (i == pos)
      std::cout << ">";
    else
      std::cout << " ";
  }
  std::cout << "] " << std::setw(12) << std::fixed << std::setprecision(2) << percentage << " %\r";
  std::cout.flush();
}
/*
set_buffergroup:设置缓冲区组选项
*/
void buffergroup::set_buffergroup(u32_t size, bool no_echo, FILE *fin, FILE *fout, bool ispadding, u64_t fsize)
{
  this->size = size;
  this->no_echo = no_echo;
  this->total_size = fsize == 0 ? 1 : fsize;
  this->buflst = new iobuffer[size];
  this->ctrl = new bufferctrl[size];
  for (int i = 0; i < size; ++i)
    buflst[i].init(fin, fout, ispadding);
};
/*
get_instance:获取实例
*/
buffergroup *buffergroup::get_instance()
{
  if (instance == NULL)
  {
    std::lock_guard<std::mutex> lock(mtx);
    if (instance == NULL)
      instance = new buffergroup();
  }
  return instance;
};
/*
del_instance:删除实例
*/
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
require_buffer_entry:获取下一个缓冲区表项
id:缓冲区标号
return:表项地址，若缓冲区已经读取完毕返回NULL
*/
u8_t *buffergroup::require_buffer_entry(const u8_t id)
{
  u8_t *result = buflst[id].get_entry();
  if (result == NULL)
  {
    ctrl[id].set_update();
    ctrl[id].wait_ready();
    if (ctrl[id].cmpstate(READY))
      result = buflst[id].get_entry();
  }
  return result;
}
/*
buffer_update:缓冲区轮流装载
*/
void buffergroup::buffer_update()
{
  size_t loadsize = buflst[turn].update_buffer(ctrl[turn].cmpstate(UPDATING), over);
  if ((loadsize != 0) && (!no_echo))
    printload(turn, loadsize);
  if (loadsize == 0)
    ctrl[turn].set_inv();
  else
    ctrl[turn].set_ready();
}
/*
final_update:缓冲区最终装载
*/
void buffergroup::final_update()
{
  buflst[turn].final_write();
  ctrl[turn].set_inv();
  if (!no_echo)
    std::cout << std::endl;
}
/*
run_buffer:缓冲区组自动装载函数
*/
void buffergroup::run_buffer()
{
  while (bufferctrl::haslive())
  {
    if (!ctrl[turn].cmpstate(INV))
    {
      ctrl[turn].wait_update();
      if (ctrl[turn].cmpstate(UPDATING) && buflst[turn].buffer_over())
        final_update();
      else
        buffer_update();
    }
    turn = (turn + 1) % size;
  }
}