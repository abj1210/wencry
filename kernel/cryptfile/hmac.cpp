#include "hmac.h"
#include <string.h>
/*
getblock:获取哈希函数块长度
type:哈希类型
return:块长度
*/
u8_t hmac::getblock(u8_t type){
    if(type==0)return 64;
    else return 0;
}
/*
getlength:获取哈希函数结果长度
type:哈希类型
return:结果长度
*/
u8_t hmac::getlength(u8_t type){
    if(type==0)return 20;
    else return 0;
}
/*
getres:计算HMAC值
key:密钥序列
fp:需验证文件指针
*/
void hmac::getres(u8_t * key, FILE *fp){
    u8_t key1[block], h1[block], h2[block+length];
    memset(key1, 0, sizeof(key1));
    memcpy(key1, key, 16);
    for(int i=0;i<block;++i)
        h1[i]=key1[i]^ipad;
    sha1Filehash filehasher(h1, fp);
    for(int i=0;i<block;++i)
        h2[i]=key1[i]^opad;
    filehasher.getres(&h2[block]);
    sha1Stringhash stringhasher(h2, block+length);
    stringhasher.getres(hmac_res);
}
/*
gethmac:获取HMAC值
key:密钥序列
fp:需验证文件指针
hmac_out:输出地址
*/
void hmac::gethmac(u8_t * key, FILE *fp, u8_t * hmac_out){
    getres(key, fp);
    memcpy(hmac_out, hmac_res, length);
}
/*
cmphmac:校验HMAC值
key:密钥序列
fp:需验证文件指针
hmac_out:待校验的HMAC值
return:校验是否成功
*/
bool hmac::cmphmac(u8_t * key, FILE *fp,const u8_t * hmac_out){
    getres(key, fp);
    for(int i=0;i<length;++i)
        if(hmac_out[i]!=hmac_res[i])return false;
    return true;
}