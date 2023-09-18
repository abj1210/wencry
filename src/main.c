#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../include/cry.h"
#include "../include/getval.h"
#include "../include/util.h"

int main(int argc, char *argv[]) {
  init();
  time_t t1, t2;
  struct vpak v1;
  if (argc == 1)
    v1 = get_v_mod1();
  else if (argc == 5 || argc == 4)
    v1 = get_v_mod2(argc, argv);
  else {
    printf("Invalid values.\n");
    return 1;
  }
  if (v1.fp == NULL)
    return -1;
  if (v1.mode == 'e' || v1.mode == 'E') {
    t1 = time(NULL);
    enc(v1.fp, v1.out, v1.key);
    t2 = time(NULL);

    unsigned char outk[128];
    memset(outk, 0, sizeof(outk));
    printf("Encrypt over! Key is: \n");
    hex_to_base64(v1.key, 16, outk);
    printf("%s\n", outk);
  } else {
    t1 = time(NULL);
    int res = dec(v1.fp, v1.out, v1.key);
    t2 = time(NULL);

    if (res == 0)
      printf("Decrypt over!\n");
    else if (res == 1)
      printf("File too short.\n");
    else if (res == 2)
      printf("Wrong key.\n");
    else if (res == 3)
      printf("File not complete.\n");
  }

  free(v1.key);
  fclose(v1.fp);
  fclose(v1.out);
  printf("Time: %lds\n", t2 - t1);
  return 0;
}