#include "resprint.h"
#include <iostream>
using namespace std;
u8_t printinv(const u8_t ret) {
  cout << "Invalid values.\r\n";
  return ret;
}
void printtime(clock_t totalTime, u8_t threads_num) {
  cout << "Time: " << totalTime / ((double)(CLOCKS_PER_SEC * threads_num))
       << "s / " << totalTime / ((double)CLOCKS_PER_SEC) << "s\r\n";
}
void printenc() { cout << "Encrypt over! \r\n"; }
void printres(int res) {
  if (res <= 0)
    cout << "Verify pass!\r\n";
  else if (res == 1)
    cout << "File too short.\r\n";
  else if (res == 2)
    cout << "Wrong key or File not complete.\r\n";
  else if (res == 3)
    cout << "File not complete.\r\n";
  else if (res == 4)
    cout << "Wrong magic number.\r\n";
  else
    cout << "Unknown res number: " << res << ".\r\n";
}