#include "console_display.h"
#include <cmath>
#include <cstdio>
#include <iomanip>
#include <iostream>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#define ISATTY _isatty
#define FILENO _fileno
#else
#include <unistd.h>
#define ISATTY isatty
#define FILENO fileno
#endif

/*################################
  模式名单源表(条目数必须与 modes.h 枚举计数一致,编译期静态断言)
################################*/
static const char *kCryptModeNames[] = {"ECB", "CBC", "CTR", "CFB", "OFB"};
static const char *kHashModeNames[] = {"sha1", "md5", "sha256"};
static_assert(sizeof(kCryptModeNames) / sizeof(kCryptModeNames[0]) == (size_t)kCryptModeCount,
              "crypt mode name table out of sync with CryptMode enum");
static_assert(sizeof(kHashModeNames) / sizeof(kHashModeNames[0]) == (size_t)kHashModeCount,
              "hash mode name table out of sync with HashType enum");

const char *cryptModeName(u8_t type)
{
  if (type >= kCryptModeCount)
    return "unknown";
  return kCryptModeNames[type];
}

const char *hashModeName(u8_t type)
{
  if (type >= kHashModeCount)
    return "unknown";
  return kHashModeNames[type];
}

/*################################
  低层输出辅助
################################*/
namespace
{
  const int LABEL_W = 24; // 标签列宽度(含": ")
  const char *RED = "\033[31m";
  const char *RESET = "\033[0m";

  // colorEnabled:仅当 stdout 是终端时启用 ANSI 颜色(管道/重定向/测试捕获时关闭)
  bool colorEnabled()
  {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE)
      return false;
    DWORD mode = 0;
    if (!GetConsoleMode(h, &mode))
      return false;
    SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    return true;
#else
    return ISATTY(FILENO(stdout)) != 0;
#endif
  }
}

void logLine(std::string label, std::string value)
{
  std::cout << std::left << std::setw(LABEL_W) << (label + ": ") << value << "\n";
}

void logError(std::string label, std::string value)
{
  if (colorEnabled())
    std::cout << RED << std::left << std::setw(LABEL_W) << (label + ": ") << value << RESET << "\n";
  else
    std::cout << std::left << std::setw(LABEL_W) << (label + ": ") << value << "\n";
}

std::string formatSize(size_t bytes)
{
  double b = (double)bytes;
  const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
  int u = 0;
  while (b >= 1024.0 && u < 4)
  {
    b /= 1024.0;
    ++u;
  }
  char buf[64];
  snprintf(buf, sizeof(buf), "%.2f %s", b, units[u]);
  return std::string(buf);
}

/*################################
  ConsoleDisplay 实现
################################*/
/* endProgress:结束活动中的进度条当前行,避免后续输出重叠 */
void ConsoleDisplay::endProgress()
{
  // 仅当进度条处于活动状态时才结束当前行,避免无进度时打印多余空行
  if (progress_active)
  {
    std::cout << "\n";
    progress_active = false;
  }
}

/* resetPercentage:重置进度计数,并在进度条活动时结束当前行 */
void ConsoleDisplay::resetPercentage()
{
  Display::resetPercentage();
  endProgress();
}

/* printTask:打印任务名 */
void ConsoleDisplay::printTask(std::string name)
{
  endProgress();
  logLine("Task", name);
}

/* createTimer:创建并启动计时器 */
Timer *ConsoleDisplay::createTimer(std::string name)
{
  Timer *timer = new Timer;
  timer->name = name;
  timer->start = std::chrono::system_clock::now();
  return timer;
}

/* printTimer:打印计时器耗时并释放 */
void ConsoleDisplay::printTimer(Timer *timer)
{
  endProgress();
  auto end = std::chrono::system_clock::now();
  auto totalTime = std::chrono::duration_cast<std::chrono::microseconds>(end - timer->start);
  // 计时器名(AES_Encryption_Time 等)转成可读标签(Encryption Time)
  std::string disp = timer->name;
  for (auto &c : disp)
    if (c == '_')
      c = ' ';
  const std::string prefix = "AES ";
  if (disp.compare(0, prefix.size(), prefix) == 0)
    disp = disp.substr(prefix.size());
  logLine(disp, std::to_string(double(totalTime.count()) * std::chrono::microseconds::period::num / std::chrono::microseconds::period::den) + "s");
  delete timer;
}

/* printEncryptDone:打印加密完成 */
void ConsoleDisplay::printEncryptDone()
{
  endProgress();
  logLine("Result", "Encryption is over!");
  over.store(true);
}

/* printVerifyResult:打印验证结果 */
void ConsoleDisplay::printVerifyResult(int res)
{
  endProgress();
  logLine("Result", this->getResultString(res));
  over.store(true);
}

/* printDecryptResult:打印解密结果 */
void ConsoleDisplay::printDecryptResult(int res)
{
  endProgress();
  if (res <= 0)
  {
    logLine("Result", "Decryption is over!");
    over.store(true);
  }
  else
    printVerifyResult(res);
}

/* printCryptMode:打印加密模式 */
void ConsoleDisplay::printCryptMode(u8_t type)
{
  endProgress();
  logLine("Crypt mode", std::to_string(type) + "/" + cryptModeName(type));
}

/* printHashMode:打印哈希模式 */
void ConsoleDisplay::printHashMode(u8_t type)
{
  endProgress();
  logLine("Hash mode", std::to_string(type) + "/" + hashModeName(type));
}

/* printPercentage:更新进度计数并打印进度条 */
void ConsoleDisplay::printPercentage(std::string name, size_t now_size, size_t total_size)
{
  (void)name;
  acc_size.fetch_add(now_size);
  this->total_size.store(total_size);
#ifndef GUI_ON
  size_t done = acc_size.load();
  size_t total = this->total_size.load();
  double percentage = total ? (100.0 * (double)done / (double)total) : 0.0;
  if (percentage > 100.0)
    percentage = 100.0;
  const int barWidth = 40;
  int pos = (int)lround(barWidth * percentage / 100.0);
  std::cout << "[";
  for (int i = 0; i < barWidth; ++i)
    std::cout << (i < pos ? '=' : (i == pos ? '>' : ' '));
  char pbuf[16];
  snprintf(pbuf, sizeof(pbuf), "%6.2f%%", percentage);
  std::cout << "] " << pbuf << "  " << formatSize(done) << " / " << formatSize(total) << "   \r";
  std::cout.flush();
  progress_active = true;
#endif
}
