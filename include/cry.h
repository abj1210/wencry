#ifndef CRY
#define CRY

void init();
void enc(FILE *fp, FILE *out, unsigned char *key);
int dec(FILE *fp, FILE *out, unsigned char *key);

#endif