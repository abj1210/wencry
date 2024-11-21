#include "multi_buffergroup.h"
#include <string>
#include <iostream>

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
fin:输入文件
ispadding:是否填充
return:返回装载状态
*/
loadstate_t iobuffer::load_buffer(FILE *fin, bool ispadding)
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
  return load == 0 ? NODATA : FULL;
}
/*
export_buffer:将缓冲区内容保存到文件
fout:输出文件
ispadding:是否填充
*/
void iobuffer::export_buffer(FILE *fout, bool ispadding)
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
set_buffergroup:设置缓冲区组选项
*/
void buffergroup::set_buffergroup(u32_t size, FILE *fin, FILE *fout, bool ispadding)
{
  this->size = size;
  this->fin = fin;
  this->fout = fout;
  this->ispadding = ispadding;
  this->buflst = new iobuffer[size];
  this->ctrl = new bufferctrl[size];
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
printload:过程打印函数
*/
void buffergroup::buffer_update(const std::function<void(std::string, size_t)> &printload)
{
  loadstate_t loadstate = NODATA;
  if (ctrl[turn].cmpstate(UPDATING))
  {
    buflst[turn].export_buffer(fout, ispadding);
    printload("Tid " + std::to_string(turn), buflst[turn].get_size());
  }
  if (!over)
    loadstate = buflst[turn].load_buffer(fin, ispadding);
  over = loadstate != FULL;
  ctrl[turn].set_ready(loadstate != NODATA);
}
/*
run_buffer:缓冲区组自动装载函数
printload:过程打印函数
*/
void buffergroup::run_buffer(const std::function<void(std::string, size_t)> &printload)
{
  do
  {
    ctrl[turn].wait_update();
    buffer_update(printload);
  } while (turn_iter());
}