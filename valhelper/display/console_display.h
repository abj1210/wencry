#ifndef VCONSOLE
#define VCONSOLE

#include "../display.h"

/*
ConsoleDisplay:终端输出子类
实现 Display 全部接口,输出"标签: 值"单栏风格、进度条与错误红显。
*/
class ConsoleDisplay : public Display
{
  bool progress_active; // 进度条是否处于活动状态(决定 resetPercentage 是否换行)

public:
  /* ConsoleDisplay:构造,初始无活动进度条 */
  ConsoleDisplay() : Display(), progress_active(false) {};
  /* 以下方法实现 Display 接口(终端输出),实现见 console_display.cpp */
  virtual void printtask(std::string name) override;
  virtual Timer *createTimer(std::string name) override;
  virtual void printTimer(Timer *timer) override;
  virtual void printenc() override;
  virtual void printresd(int res) override;
  virtual void printresv(int res) override;
  virtual void printctype(u8_t type) override;
  virtual void printhtype(u8_t type) override;
  virtual void resetPercentage() override;
  virtual void printpercentage(std::string name, size_t now_size, size_t total_size) override;
};

#endif
