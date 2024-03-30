#include "cry.h"
#include <time.h>
#include <iostream>
/*################################
  HMAC函数
################################*/

/*
getres:计算HMAC值
key:密钥序列
fp:需验证文件指针
*/
void hmac::getres(u8_t *key, FILE *fp)
{
    u8_t block = hashmaster.getblen(), length = hashmaster.gethlen();
    u8_t key1[block], h1[block], h2[block + length];
    memset(key1, 0, sizeof(key1));
    memcpy(key1, key, 16);
    for (int i = 0; i < block; ++i)
        h1[i] = key1[i] ^ ipad;
    hashmaster.getFileOffsetHash(fp, h1, &h2[block]);
    for (int i = 0; i < block; ++i)
        h2[i] = key1[i] ^ opad;
    hashmaster.getStringHash(h2, block + length, hmac_res);
}
/*
gethmac:获取HMAC值
key:密钥序列
fp:需验证文件指针
hmac_out:输出地址
*/
void hmac::gethmac(u8_t *key, FILE *fp, u8_t *hmac_out)
{
    getres(key, fp);
    memcpy(hmac_out, hmac_res, hashmaster.gethlen());
}
/*
cmphmac:校验HMAC值
key:密钥序列
fp:需验证文件指针
hmac_out:待校验的HMAC值
return:校验是否成功
*/
bool hmac::cmphmac(u8_t *key, FILE *fp, const u8_t *hmac_out)
{
    getres(key, fp);
    for (int i = 0; i < hashmaster.gethlen(); ++i)
        if (hmac_out[i] != hmac_res[i])
            return false;
    return true;
}

/*################################
  文件头辅助函数
################################*/
/*
getIV:获取初始向量(从输入)
r_buf:随机缓冲数组
iv:初始向量数组
*/
void FileHeader::getIV(const u8_t *r_buf, u8_t *iv)
{
    Hashmaster hm(Hashmaster::SHA1);
    hm.getStringHash(r_buf, strlen((const char *)r_buf), iv);
    for (int i = 1; i < num; ++i)
        hm.getStringHash(iv + (20 * (i - 1)), 20, iv + (20 * i));
}
/*
getIV:获取初始向量(从文件)
fp:文件指针
iv:初始向量数组
*/
void FileHeader::getIV(FILE *fp, u8_t *iv)
{
    fseek(fp, 28, SEEK_SET);
    for (int i = 0; i < num; ++i)
    {
        if (fread(iv + (20 * i), 1, 20, fp) != 20)
            printf("Error reading.\n");
        return;
    }
}
/*
getFileHeader:构造加密文件头
iv:初始向量数组
*/
void FileHeader::getFileHeader(u8_t *iv)
{
    u8_t padding[21];
    padding[20] = 0;
    u64_t mn = Magic_Num;
    fwrite(&mn, 1, 8, out);
    fwrite(padding, 1, 20, out);
    for (int i = 0; i < num; ++i)
    {
        fwrite(iv + (20 * i), 1, 20, out);
    }
}
/*
checkMn:检查魔数
*/
bool FileHeader::checkMn()
{
    fseek(fp, 0, SEEK_SET);
    u64_t mn = 0;
    int sum = fread(&mn, 1, 8, fp);
    if (sum != 8)
    {
        return false;
    }
    return (mn == Magic_Num);
}
/*
checkHmac:获得HMAC
return:HMAC地址
*/
u8_t *FileHeader::getHmac()
{
    fseek(fp, 8, SEEK_SET);
    int sum = fread(hash, 1, 20, fp);
    if (sum != 20)
    {
        return NULL;
    }
    return hash;
}
