#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../include/cry.h"

int main(int argc, char *argv[]) {
  init();
  time_t t1, t2;
  if (argc == 1) {
    printf("Need encrypt or decrypt?(e/d) ");
    char mode;
    scanf("%c", &mode);
    printf("File name:\n");
    char fn[128], outn[138], kn[128];
    scanf("%s", fn);
    FILE *fp = fopen(fn, "rb");
    if (fp == NULL) {
      printf("File not found.\n");
      return 1;
    }
    unsigned char *key;

    if (mode == 'e' || mode == 'E') {
      printf("Need generate a new key?(y/n) ");
      char flag;
      scanf("%*[\n]%c", &flag);
      if (flag == 'y' || flag == 'Y') {
        key = gen_key();
      } else {
        printf("Enter 128 bits (16 bytes) key in hexadecimal:\n");
        scanf("%s", kn);
        key = read_key(kn);
      }
      sprintf(outn, "%s.wenc", fn);
      FILE *out = fopen(outn, "wb+");
      t1 = time(NULL);
      enc(fp, out, key);
      t2 = time(NULL);

      printf("Encrypt over! Key is: \n");
      for (int i = 0; i < 16; i++) printf("%02x", key[i]);
      printf("\n");

      free(key);
      fclose(fp);
      fclose(out);
    } else {
      char decn[128];
      FILE *out;
      printf("Need a new name for decrypted file?(y/n) ");
      char flag;
      scanf("%*[\n]%c", &flag);
      if (flag == 'y' || flag == 'Y') {
        printf("Enter new name:\n");
        scanf("%s", decn);
        out = fopen(decn, "wb+");
      } else {
        sprintf(outn, "%s.wdec", fn);
        out = fopen(outn, "wb+");
      }
      printf("Enter 128 bits (16 bytes) key in hexadecimal:\n");
      scanf("%s", kn);
      key = read_key(kn);
      t1 = time(NULL);
      int res = dec(fp, out, key);
      t2 = time(NULL);
      if (res == 0)
        printf("Decrypt over!\n");
      else if (res == 1)
        printf("File too short.\n");
      else if (res == 2)
        printf("Wrong key.\n");
      else if (res == 3)
        printf("File not complete.\n");

      free(key);
      fclose(fp);
      fclose(out);
    }

  } else if (argc == 5 || argc == 4) {
    if (strcmp(argv[1], "-e") == 0) {
      FILE *fp = fopen(argv[2], "rb");
      if (fp == NULL) {
        printf("File not found.\n");
        return 1;
      }
      unsigned char *key;
      if (strcmp(argv[3], "G") == 0) {
        key = gen_key();
      } else {
        key = read_key(argv[3]);
      }
      unsigned char outn[138];
      if (argc == 4) {
        sprintf(outn, "%s.wenc", argv[2]);
      } else {
        sprintf(outn, "%s.wenc", argv[4]);
      }
      FILE *out = fopen(outn, "wb+");
      t1 = time(NULL);
      enc(fp, out, key);
      t2 = time(NULL);
      printf("Encrypt over! Key is: \n");
      for (int i = 0; i < 16; i++) printf("%02x", key[i]);
      printf("\n");

      free(key);
      fclose(fp);
      fclose(out);
    } else if (strcmp(argv[1], "-d") == 0) {
      FILE *fp = fopen(argv[2], "rb");
      if (fp == NULL) {
        printf("File not found.\n");
        return 1;
      }

      unsigned char *key;
      key = read_key(argv[3]);

      FILE *out;
      if (argc == 4) {
        unsigned char outn[138];
        sprintf(outn, "%s.denc", argv[2]);
        out = fopen(outn, "wb+");
      } else {
        out = fopen(argv[4], "wb+");
      }
      t1 = time(NULL);
      int res = dec(fp, out, key);
      t2 = time(NULL);
      if (res == 0)
        printf("Decrypt over!\n");
      else if (res == 1)
        printf("File too short.\n");
      else if (res == 2)
        printf("Wrong key.\n");
      else if (res == 3)
        printf("File not complete.\n");

      free(key);
      fclose(fp);
      fclose(out);

    } else
      return 1;
  } else {
    printf("Invalid values.\n");
    return 1;
  }
  printf("Time: %lds\n", t2 - t1);
  return 0;
}