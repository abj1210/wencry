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
    fseek(fp, FILE_IV_MARK, SEEK_SET);
    for (int i = 0; i < num; ++i)
        fread(iv + (20 * i), 1, 20, fp);
}
/*
getFileHeader:构造加密文件头
iv:初始向量数组
*/
void FileHeader::getFileHeader(u8_t *iv)
{
    u8_t padding[PADDING];
    memset(padding, 0, sizeof(padding));
    u64_t mn = Magic_Num;
    fwrite(&mn, 1, 8, out);
    fwrite(padding, 1, PADDING, out);
    for (int i = 0; i < num; ++i)
    {
        fwrite(iv + (20 * i), 1, 20, out);
    }
    printf("aaaa\n");
}
/*
checkMn:检查魔数
*/
bool FileHeader::checkMn()
{
    fseek(fp, FILE_MN_MARK, SEEK_SET);
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
    fseek(fp, FILE_HMAC_MARK, SEEK_SET);
    int sum = fread(hash, 1, 20, fp);
    if (sum != 20)
    {
        return NULL;
    }
    return hash;
}

/*################################
  结果打印辅助函数
################################*/

/*
printinv: 打印非法
return: 返回值
*/
u8_t ResultPrint::printinv(const u8_t ret)
{
  if(!no_echo)std::cout << "Invalid values.\r\n";
  return ret;
}
/*
printtime: 打印时间
totalTime: 总时间
threads_num: 线程数
*/
void ResultPrint::printtime(clock_t totalTime)
{
  if(!no_echo)std::cout << "Time: " << totalTime / ((double)(CLOCKS_PER_SEC * threads_num))
            << "s / " << totalTime / ((double)CLOCKS_PER_SEC) << "s\r\n";
}
/*
printenc: 打印加密结果
*/
void ResultPrint::printenc() { if(!no_echo)std::cout << "Encrypt over! \r\n"; }
/*
printres: 打印解密结果
res: 解密结果
*/
void ResultPrint::printres(int res)
{
  if(!no_echo)
  {
    if (res <= 0)
        std::cout << "Verify pass!\r\n";
    else if (res == 1)
        std::cout << "File too short.\r\n";
    else if (res == 2)
        std::cout << "Wrong key or File not complete.\r\n";
    else if (res == 3)
        std::cout << "File not complete.\r\n";
    else if (res == 4)
        std::cout << "Wrong magic number.\r\n";
    else
        std::cout << "Unknown res number: " << res << ".\r\n";
  }
}