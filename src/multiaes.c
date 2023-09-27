#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/aes.h"
#include "../include/util.h"

struct Wthread tlist[NUM_THREADS];



void init_threads(){
    int rc;
    for(int i=0;i<NUM_THREADS;i++) {
        tlist[i].tid=i;
        tlist[i].taskover=0;
        rc=pthread_create(&tlist[i].pts,NULL, pt_runaes, (void *)&tlist[i].tid);
    }
};

void pt_marster(){

}
void pt_runaes(void * Arg){
    
}