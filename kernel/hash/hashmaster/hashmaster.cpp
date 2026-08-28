#include "hashmaster.h"
#include "sha_ni.h"
#include <string.h>
/*
模块概述:哈希算法框架实现
Hashmaster 的通用框架(getStringHash、增量接口与工厂逻辑)已在 hashmaster.h 中
以内联方式实现,本翻译单元不提供独立的函数定义,仅保留该编译单元以维持构建目标。
SHA1/SHA256 的末尾块填充与摘要输出见 sha1.cpp/sha256.cpp,
MD5 软件实现见 md5.cpp,整块硬件加速见 sha_ni.cpp。
*/
