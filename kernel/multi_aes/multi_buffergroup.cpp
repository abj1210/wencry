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
load_buffer:更新缓冲区
return:返回装载状态
*/
loadstate_t iobuffer::load_buffer()
{
  u32_t load = fread(b, 1, sum, fin);
  bool readover = feof(fin);
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
    isfinal = true;
    return FINAL;
  }
  return load == 0 ? NO_DATA : FULL;
}
/*
export_buffer:将缓冲区内容保存到文件
*/
void iobuffer::export_buffer()
{
  if (isfinal)
  {
    u8_t padding = ispadding ? 0 : b[now - 1][15];
    fwrite(b, 1, (now << 4) - padding, fout);
  }
  else
    fwrite(b, 1, sum, fout);
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
    cv_ready.wait(locker);
  locker.unlock();
}
/*
wait_update:等待可以装载
*/
void bufferctrl::wait_update()
{
  std::unique_lock<std::mutex> locker(lock);
  while (state != UPDATING && state != EMPTY)
    cv_update.wait(locker);
  locker.unlock();
}
/*
set_ready:设置就绪或无效状态
load:装载是否不为空
*/
void bufferctrl::set_ready(bool load)
{
  std::unique_lock<std::mutex> locker(lock);
  if (load)
    state = READY;
  else
  {
    state = INV;
    live_num--;
  }
  cv_ready.notify_all();
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
    cv_update.notify_all();
  }
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
  if (size == 0)
    return;
  now_size += size;
  double percentage = 100.0 * ((double)now_size / (double)(total_size));
#ifndef GUI_ON
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
#else
  this->percentage = percentage;
#endif
}
/*
set_buffergroup:设置缓冲区组选项
*/
void buffergroup::set_buffergroup(u32_t size, bool no_echo, FILE *fin, FILE *fout, bool ispadding, u64_t fsize)
{
  this->percentage = 0;
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
turn_iter:缓冲区序号迭代
return:迭代是否成功
*/
bool buffergroup::turn_iter()
{
  if (!bufferctrl::haslive())
    return false;
  do
    turn = (turn + 1) % size;
  while (ctrl[turn].cmpstate(INV));
  return true;
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
  loadstate_t loadstate = NO_DATA;
  if (ctrl[turn].cmpstate(UPDATING)){
    buflst[turn].export_buffer();
    if (!no_echo)
      printload(turn, buflst[turn].get_size());
  }
  if (!over)
    loadstate = buflst[turn].load_buffer();
  over = loadstate != FULL;
  ctrl[turn].set_ready(loadstate != NO_DATA);
}
/*
run_buffer:缓冲区组自动装载函数
*/
void buffergroup::run_buffer()
{
  do
  {
    ctrl[turn].wait_update();
    buffer_update();
  } while (turn_iter());
  if (!no_echo)
    std::cout << "\r\n";
}