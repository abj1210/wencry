#include "key.h"
#include "util.h"
#include <iostream>
using namespace std;
void printload(const u8_t id) {
  cout << "Buffer of thread id " << (const u32_t)id << " loaded "
       << (iobuffer::BUF_SZ >> 16) << "MB data.\r\n";
}
u8_t printinv(const u8_t ret) {
  cout << "Invalid values.\r\n";
  return ret;
}
bool printterr() {
  if (THREADS_NUM >= MAX_THREADS) {
    cout << "Invalid threads number!\r\n";
    return true;
  } else
    return false;
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
void printtime(clock_t totalTime) {
  cout << "Time: " << totalTime / ((double)(CLOCKS_PER_SEC * THREADS_NUM))
       << "s / " << totalTime / ((double)CLOCKS_PER_SEC) << "s\r\n";
}
void printkey(keyhandle *key) {
  char outk[128];
  key->get_initkey((u8_t *)outk);
  cout << "Key is:\r\n" << outk << "\r\n";
}