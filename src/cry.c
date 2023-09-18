#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../include/aes.h"
#include "../include/cry.h"
#include "../include/sha1.h"
#include "../include/util.h"

struct buffer ibuf, obuf;
unsigned int read_buffer(FILE *fp, unsigned char *block) {
  unsigned int res = 0;
  if (ibuf.now == BUF_SZ || ibuf.load == 0) {
    unsigned int sum = fread(ibuf.b, 1, BUF_SZ << 4, fp);
    ibuf.tail = sum & 0xf;
    ibuf.total = sum >> 4;
    ibuf.now = 0;
    ibuf.load = 1;
  }

  if (ibuf.now == ibuf.total) {
    memcpy(block, ibuf.b[ibuf.now], ibuf.tail);
    res = ibuf.tail;
    ibuf.tail = 0;
  } else {
    memcpy(block, ibuf.b[ibuf.now], 16);
    res = 16;
    ibuf.now++;
  }
  return res;
}
unsigned int bufferover() {
  return (ibuf.now == ibuf.total) && (ibuf.now != BUF_SZ) && (ibuf.tail == 0);
}
void write_buffer(FILE *fp, unsigned char *block) {
  memcpy(obuf.b[obuf.total], block, 16);
  obuf.total++;
  if (obuf.total == BUF_SZ) {
    fwrite(obuf.b, 1, BUF_SZ << 4, fp);
    obuf.total = 0;
  }
}
void final_write(FILE *fp) { fwrite(obuf.b, 1, obuf.total << 4, fp); }

void init() { srand(time(NULL)); }

unsigned char *gen_key() {
  unsigned char *key = malloc(16 * sizeof(unsigned char));
  for (int i = 0; i < 16; i++) {
    key[i] = rand() & 0xff;
  }
  return key;
}

int cmphash(unsigned char *h1, unsigned char *h2) {
  for (int i = 0; i < 20; i++) {
    if (h1[i] != h2[i])
      return 1;
  }
  return 0;
}

void enc(FILE *fp, FILE *out, unsigned char *key) {
  unsigned char *hash;
  unsigned short round = 0;
  unsigned int bnum = 0;
  hash = getsha1s(key, 16);
  fwrite(hash, 1, 20, out);
  fwrite(hash, 1, 20, out);
  free(hash);
  unsigned char z = 0;
  fwrite(&z, 1, 1, out);
  printf("Begin to encrypt.\n");
  printf("Encrypted: 00000000 MB.");
  fflush(stdout);
  unsigned char block[16];
  unsigned char res[16];
  initgen(key);
  while (1) {
    round++;
    if (round == 0) {
      bnum++;
      printf("\b\b\b\b\b\b\b\b\b\b\b\b");
      printf("%08d MB.", bnum);
      fflush(stdout);
    }
    unsigned char sum = read_buffer(fp, block);
    runaes_128bit(block, res);
    write_buffer(out, res);
    if (sum != 16) {
      final_write(out);
      fseek(out, 40, SEEK_SET);
      fwrite(&sum, 1, 1, out);
      break;
    }
  }
  printf("\n Encrypted.\n");
  printf("Begin to hash.\n");
  fseek(out, 41, SEEK_SET);
  hash = getsha1f(out);
  fseek(out, 20, SEEK_SET);
  fwrite(hash, 1, 20, out);
  free(hash);
  printf("Execute over!\n");
  return;
}

int dec(FILE *fp, FILE *out, unsigned char *key) {
  printf("Begin to check.\n");
  unsigned char hash[20];
  int sum = fread(hash, 1, 20, fp);
  if (sum != 20)
    return 1;
  unsigned char *chash = getsha1s(key, 16);
  if (cmphash(chash, hash) != 0) {
    free(chash);
    return 2;
  }
  free(chash);
  printf("Key check OK.\n");

  sum = fread(hash, 1, 20, fp);
  if (sum != 20)
    return 1;

  unsigned char tail;
  unsigned short round = 0;
  unsigned int bnum = 0;
  int rx = fread(&tail, 1, 1, fp);

  chash = getsha1f(fp);
  if (cmphash(chash, hash) != 0) {
    free(chash);
    return 3;
  }

  free(chash);
  printf("File check OK.\n");

  fseek(fp, 41, SEEK_SET);
  printf("Begin to decrypt.\n");
  printf("Decrypted: 00000000 MB.");
  fflush(stdout);
  unsigned char block[16];
  unsigned char res[16];
  initgen(key);
  while (1) {
    round++;
    if (round == 0) {
      bnum++;
      printf("\b\b\b\b\b\b\b\b\b\b\b\b");
      printf("%08d MB.", bnum);
      fflush(stdout);
    }
    unsigned char sum = read_buffer(fp, block);
    decaes_128bit(block, res);
    if (bufferover()) {
      final_write(out);
      fwrite(res, 1, tail, out);
      break;
    } else
      write_buffer(out, res);
  }
  printf("\n Decrypted.\n");

  printf("Execute over!\n");
  return 0;
}