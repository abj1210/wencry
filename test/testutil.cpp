#include "testutil.h"
#include <string.h>
FILE *genfile(const char *str) {
  remove("test.txt");
  FILE *fp = fopen("test.txt", "w");
  fputs(str, fp);
  fclose(fp);
  fp = fopen("test.txt", "rb");
  return fp;
}
void gethex(const char *str, unsigned char *out) {
  int hex = -1;
  int j = 0;
  for (int i = 0; i < strlen(str); ++i) {
    if (hex == -1) {
      if (str[i] >= '0' && str[i] <= '9')
        hex = str[i] - '0';
      else if (str[i] >= 'a' && str[i] <= 'f')
        hex = str[i] - 'a' + 10;
      else if (str[i] >= 'A' && str[i] <= 'F')
        hex = str[i] - 'A' + 10;
    } else {
      hex = hex << 4;
      if (str[i] >= '0' && str[i] <= '9')
        hex += str[i] - '0';
      else if (str[i] >= 'a' && str[i] <= 'f')
        hex += str[i] - 'a' + 10;
      else if (str[i] >= 'A' && str[i] <= 'F')
        hex += str[i] - 'A' + 10;
      out[j++] = hex & 0xff;
      hex = -1;
    }
  }
}
bool cmpstr(const unsigned char *s1, const unsigned char *s2, int n) {
  for (int i = 0; i < n; i++) {
    printf("%d: 0x%02x 0x%02x\n", i, s1[i], s2[i]);
    if (s1[i] != s2[i])
      return false;
  }
  return true;
}
