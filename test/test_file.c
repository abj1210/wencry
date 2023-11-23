#include <stdio.h>
#include <string.h>
#define BUFFER_SIZE 0x1000000
char buffer[BUFFER_SIZE];
int main(int argc, char *argv[]){
    if(argc!=2)return 1;
    FILE * fp = fopen(argv[1], "wb+");
    fwrite(buffer, 1, BUFFER_SIZE, fp);
    fwrite(buffer, 1, BUFFER_SIZE, fp);
    fclose(fp);
    return 0;
}