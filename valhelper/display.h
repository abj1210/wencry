#ifndef VDISP
#define VDISP

#include "modes.h"
#include <atomic>
#include <chrono>
#include <cstddef>
#include <string>

typedef unsigned char u8_t;

/*
crypt_mode_name:获取加密模式名称(单源)
type:模式码(0=ECB..4=OFB)
return:模式名(非法返回 "unknown")
*/
const char *crypt_mode_name(u8_t type);
/*
hash_mode_name:获取哈希模式名称(单源)
type:模式码(0=sha1,1=md5,2=sha256)
return:模式名(非法返回 "unknown")
*/
const char *hash_mode_name(u8_t type);

/*
strlog:格式化打印一行"标签: 值"(标签左对齐到固定宽度)
label:标签(自动追加": ")
value:值
*/
void strlog(std::string label, std::string value);
/*
strerr:红色高亮打印一行错误信息(终端支持ANSI且为TTY时生效)
label:标签(自动追加": ")
value:值
*/
void strerr(std::string label, std::string value);
/*
format_size:将字节数格式化为人类可读字符串(1024进制)
bytes:字节数
return:形如 "1.00 GiB" 的字符串
*/
std::string format_size(size_t bytes);

/*
计时器类
*/
struct Timer
{
  std::chrono::system_clock::time_point start;
  std::string name;
};

/*
Display:结果打印抽象基类(统一命令解析与内核执行的输出)
子类:
  - ConsoleDisplay:终端输出(见 display/console_display.h)
  - SilentDisplay:静默输出(见 display/silent_display.h)
*/
class Display
{
protected:
  std::atomic<size_t> acc_size;
  std::atomic<size_t> total_size;
  std::atomic<bool> over;

public:
  Display() : acc_size(0), total_size(1), over(false) {};
  virtual ~Display() {};
  virtual void printtask(std::string name) = 0;
  virtual u8_t printinv(const u8_t ret) = 0;
  virtual Timer *createTimer(std::string name) = 0;
  virtual void printTimer(Timer *timer) = 0;
  virtual void printenc() = 0;
  virtual void printresd(int res) = 0;
  virtual void printresv(int res) = 0;
  virtual void printctype(u8_t type) = 0;
  virtual void printhtype(u8_t type) = 0;
  virtual void printpercentage(std::string name, size_t now_size, size_t total_size) = 0;
  virtual void resetPercentage() { acc_size.store(0); };
  std::string getResStr(int res)
  {
    if (res <= 0)
      return "Verification passed!";
    else if (res == 1)
      return "Input file is too short.";
    else if (res == 2)
      return "Wrong key or File not complete.";
    else if (res == 3)
      return "Aes / hash mode not match.";
    else if (res == 4)
      return "Wrong magic number.";
    else
      return "Unknown res number: " + std::to_string(res);
  }
  int getPercentage() const
  {
    size_t t = total_size.load();
    size_t a = acc_size.load();
    if (t == 0)
      return 0;
    int p = (int)(100 * ((double)a / (double)t));
    if (p < 0)
      p = 0;
    if (p > 100)
      p = 100;
    return p;
  };
  bool isOver() const { return over.load(); };
};

#endif
