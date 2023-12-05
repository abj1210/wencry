
#include <iostream>
using namespace std;
typedef unsigned char u8_t;
typedef unsigned int u32_t;
u8_t printinv(const u8_t ret) {
  cout << "Invalid values.\r\n";
  return ret;
}
void printres(u8_t res) {
  if (res == 0)
    cout << "Decrypt over!\r\n";
  else if (res == 1)
    cout << "File too short.\r\n";
  else if (res == 2)
    cout << "Wrong key.\r\n";
  else if (res == 3)
    cout << "File not complete.\r\n";
  else if (res == 4)
    cout << "Wrong magic number.\r\n";
}
void printenc() { cout << "Encrypt over! \r\n"; }
void printtime(clock_t totalTime, u8_t threads_num) {
  cout << "Time: " << totalTime / ((double)(CLOCKS_PER_SEC * threads_num))
       << "s / " << totalTime / ((double)CLOCKS_PER_SEC) << "s\r\n";
}