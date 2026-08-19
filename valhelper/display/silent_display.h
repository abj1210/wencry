#ifndef VSILENT
#define VSILENT

#include "../display.h"

/*
SilentDisplay:静默输出子类
不打印任何内容,仅维护进度计数与完成标志(用于 -n/--no_echo 或测试)。
*/
class SilentDisplay : public Display
{
public:
  /* SilentDisplay:构造,不打印任何内容 */
  SilentDisplay() : Display() {};
  /* 以下方法实现 Display 接口(静默,仅维护进度计数与完成标志) */
  virtual void printtask(std::string) override {};
  virtual Timer *createTimer(std::string) override { return NULL; };
  virtual void printTimer(Timer *) override {};
  virtual void printenc() override { over.store(true); };
  virtual void printresd(int) override { over.store(true); };
  virtual void printresv(int) override { over.store(true); };
  virtual void printctype(u8_t) override {};
  virtual void printhtype(u8_t) override {};
  virtual void resetPercentage() override { acc_size.store(0); };
  virtual void printpercentage(std::string, size_t now_size, size_t total_size) override
  {
    this->total_size.store(total_size);
    this->acc_size.fetch_add(now_size);
  };
};

#endif
