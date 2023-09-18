#ifndef CRY
#define CRY

#include <stdio.h>
#define BUF_SZ 0x100000

unsigned int read_buffer(FILE* fp, unsigned char* block);
unsigned int bufferover();
void write_buffer(FILE* fp, unsigned char* block);
void final_write(FILE* fp);

void enc(FILE* fp, FILE* out, unsigned char* key);
int dec(FILE* fp, FILE* out, unsigned char* key);
unsigned char* gen_key();
unsigned char* read_key(char* s);
int cmphash(unsigned char* h1, unsigned char* h2);

void init();

#endif