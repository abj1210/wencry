# 数据加密解密程序

作者：闻嘉迅  
日期：2026.8.10 (最后修改)  
版本：v4.1.0

**默认4+2线程,CBC加密模式,SHA1哈希**  
**Windows原生处理速度可达1000MB/s以上**  
**内存占用小于90MB**   

## 加密原理

**加密**  
根据输入或随机数计算IV
根据选定的加密模式,使用密钥和IV(初始向量)进行AES128加密  
根据密文和密钥生成HMAC
得到最终的加密文件  

**解密**  
先检查魔数,确定为正确加密后的文件  
再提取文件的HMAC与计算的HMAC比较,确保文件完整  
提取IV  
最后根据加密模式对文件进行AES128解密  
得到解密后的文件  

**加密文件结构**  
加密后的文件带有后缀.wenc,其结构如下:
- 偏移 0   8字节  魔数 0xA5C3A5C3A5C3A5C3
- 偏移 8   1字节  加密模式 ctype(0=ECB..4=OFB)
- 偏移 9   1字节  哈希模式 htype(0=sha1,1=md5,2=sha256)
- 偏移 10  38字节 HMAC区(加密后写入,长度取决于htype;offset47恒空闲,用于记录线程数num)
- 偏移 48  20*num字节 每线程IV
- 之后    密文(含PKCS7填充)

## 文件结构

- **wencry:项目文件夹**  
  - main.cpp:主函数   
  - config.h.in:配置文件  
  - **valget:获取参数包相关文件夹**
    - getval.h:获取参数包的头文件  
    - getopts.cpp:负责获取控制台操作参数
    - getval1.cpp:负责获取用户输入操作参数
    - information.cpp:负责打印版本信息和帮助信息
    - **base64:base64转换文件夹**
      - base64.h:十六进制序列与base64编码的相互转换
      - base64.cpp:负责进行base64的编码和解码   
  - **kernel:加解密核心文件夹**  
    - cry.h:加解密流程相关的头文件  
    - cry.cpp:负责整体加解密流程  
    - fheader.cpp:负责文件头的生成和验证流程
    - **multi_aes:多线程进行aes加解密函数的文件夹**
      - multicry.h:多线程进行aes加解密的相关头文件
      - multicry.cpp:多线程进行aes加解密的函数实现
      - multi_buffergroup.h:多线程缓冲区组的相关头文件 
      - multi_buffergroup.cpp:多线程缓冲区组的实现
      - **aesmode:应用多种aes加密模式加密器的文件夹**
        - aesmode.h:不同模式的aes加密器的相关头文件
        - aesmode.cpp:不同模式的aes加密器的实现
        - aes.h:AES加解密相关的头文件  
        - aes.cpp:负责AES加解密的各流程  
        - tab.h:加解密所需的数表
    - **hash:哈希函数文件夹**
      - sha1.cpp:负责产生sha1哈希的流程  
      - md5.cpp:负责产生md5哈希的流程 
      - hashmaster.h:产生不同类型哈希的头文件
      - hashmaster.cpp:产生不同类型哈希类的实现  
      - hashbuffer.h:哈希输入缓冲区头文件  
      - hashbuffer.cpp:哈希输入缓冲区的实现
  - **test:测试文件夹**
    - testutil.h:基础组件测试相关函数的头文件
    - testutil.cpp:基础组件测试相关函数的实现
    - test.h:测试相关函数的头文件
    - test.cpp:测试相关函数的实现
    - testutest.cpp:testutil函数测试
    - testsha1.cpp:sha1哈希测试
    - testaes.cpp:单块aes测试
    - testbase64.cpp:base64编码测试
    - testhmac.cpp:HMAC编码测试
    - testECB.cpp:ECB模式下多块aes测试
    - testCBC.cpp:CBC模式下多块aes测试
    - testCTR.cpp:CTR模式下多块aes测试
    - testCFB.cpp:CFB模式下多块aes测试
    - testOFB.cpp:OFB模式下多块aes测试
    - testsmall.cpp:小文件加解密测试
    - testsmode.cpp:不同加密模式下文件加解密测试  
    - testshash.cpp:不同哈希模式下文件加解密测试  
    - testbig.cpp:大文件加解密测试
    - testspeed.cpp:文件加密速度测试(含吞吐量断言)
    - testvectors.cpp:NIST/标准向量测试(AES各模式、FIPS-197、哈希填充边界、HMAC参考向量、CTR进位、哈希缓冲区重载)
    - testboundary.cpp:边界尺寸往返、线程数变化、文件头布局、失败路径、CLI参数错误路径测试
    - testinteractive.cpp:交互式模式子进程E2E测试(加密/解密/验证/错误模式/密钥校验重试/随机密钥)

具体函数和结构体作用与解释参阅源代码注释.  

## 使用方法

**创建构建目录**  
使用`mkdir ./build`命令创建构建目录,`cd ./build`命令进入构建目录.  
**构建并编译**  
使用`cmake -DCMAKE_BUILD_TYPE=[Debug/Release] ..`构建Debug或Release版本,`make`命令进行编译.  
**测试**
在项目编译后使用`ctest`命令进行测试.  
(若想关闭测试则需在根目录`CMakeLists.txt`中关闭`BUILD_TEST`选项.)  

### Windows 环境构建

项目支持在原生 Windows(MSVC/Visual Studio Build Tools)下编译运行,无需WSL:

1. 安装 [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/) 或 Visual Studio,勾选"C++ 生成工具"(含 MSVC 编译器、CMake、Ninja)。
2. 在"开发人员 PowerShell"(Developer PowerShell)中执行:
   ```bat
   cmake -S . -B build\win -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TEST=OFF
   cmake --build build\win
   ```
   (测试需要 GTest,Windows 下未配置时可关闭 `BUILD_TEST`;也可用 vcpkg/`-DBUILD_TEST=ON` + FetchContent 方式引入。)
3. 生成的 `build\win\Wencry.exe` 直接运行:
   ```bat
   Wencry.exe -e -i in.txt --cmode 1 -o in.txt.wenc
   Wencry.exe -d -i in.txt.wenc -o out.txt -k 密钥
   ```

Windows 兼容说明:
- 命令行参数解析在 Windows 下使用自带的 `valget/getopt_port.cpp`(POSIX `getopt_long` 移植),Linux 仍用系统 getopt。
- AES-NI / SHA-NI 内联汇编式 intrinsics 在 MSVC x64 上直接可用,无需额外 `/arch` 开关。
- 源码为 UTF-8(含中文注释),构建时已加 `/utf-8`。

**生成 Visual Studio 解决方案**:
在"开发人员 PowerShell"中执行(需使用 VS 自带的 CMake 或 CMake ≥4.2,以识别 VS 2026 生成器):
   ```bat
   cmake -G "Visual Studio 18 2026" -A x64 -S . -B build_vs -DBUILD_TEST=OFF
   cmake --build build_vs --config Release
   ```
生成 `build\vs\Wencry.slnx`(VS 2026 新解决方案格式,含 Wencry/Wenkernel/Multiaes/Hash/Aes/Base64/CMDvals 各工程),可直接用 Visual Studio 打开编译、调试。若需传统 `.sln`,可改用 `-G "Visual Studio 17 2022"`。

**以下操作均在./build目录下进行**  

**若在无参数下执行，则可根据提示完成操作**  
**命令行参数模式的介绍如下**

### 选择模式

- `-e`/`--encode` 为加密模式
- `-d`/`--decode` 为解密模式
- `-v`/`--verify` 为验证模式
- `-V`/`--version` 为查看版本
- `-h`/`--help` 为查看帮助

### 参数设置

- `-i`/`--input` + `[inputfile]` 指示输入文件路径
- `-o`/`--output` + `[outputfile]` 指示输出文件路径，缺省为输入文件名+".wenc"后缀
- `-k`/`--key` + `[key]` 指示ase64编码后的16字节16进制密钥(编码后共24位) ，缺省为随机生成的密钥
- `--cmode` + `[mode]` 指示加密模式(参见加密原理部分)  
- `--hmode` + `[mode]` 指示哈希模式(参见HMAC部分) 
- `-n`/`--no_echo` 此选项表示隐藏处理信息

### 示例

- 加密: ./Wencry -e -i ../a.mp4 --cmode 2 -o ../a.mp4.wenc
- 解密: ./Wencry -d -i ../a.mp4.wenc -o ../aa.mp4 -k Z8Zpc1HSuwpzbqr8vvjRg==

## 多线程  
 
若想改变线程数量,则可改变`cry.h`中的宏`THREAD_NUM`的值.  
相关代码位于`multicry.cpp`和`multi_buffergroup.cpp`中.  

**线程数写入文件头**:自v4.0.1起,加密文件头的offset 47字节记录了加密时的线程数,解密/验证时自动从文件读取(旧格式文件该字节为0,按4线程处理).因此不同线程数构建的程序可以互相解密文件,修改`THREAD_NUM`不再破坏已有文件.

- **多线程流水线原理**  
加解密采用"读线程--工作线程--写线程"三级流水线:读线程按顺序`fread`装载数据块,多个工作线程就地AES加解密,写线程按序号`fwrite`导出,读写两个方向可重叠,不再由单一维护线程串行承担全部文件I/O.  
每个工作线程有唯一`id`,chunk k固定由线程`k%N`处理,以保持各线程AES的IV链一致.  
详细协作逻辑见`multi_buffergroup.cpp`注释.

## WSL运行提速建议

- `/mnt/d`等9p挂载盘I/O较慢,可在`/etc/wsl.conf`的`[automount]`节开启缓存以显著提升文件读写速度,例如:
  ```ini
  [automount]
  enabled = true
  options = "metadata,umask=22,fmask=11,cache=mmap"
  ```
- 处理大文件时,将数据放在WSL原生ext4(如`/tmp`或`~/`)上再加密,通常比`/mnt/d`快数倍.
- 实测单次加解密的速度上限主要受文件I/O总吞吐限制(加密需读明文+写密文共两遍,解密需回读密文验HMAC+读密文解密共两遍),I/O越快吞吐越高.

详细过程参阅相关代码.  

## 加密流程更新

2.9,3.0版本更新大幅改动了加密流程,通过增加HMAC,AES加密模式,pcks7填充等方法进一步增加了安全性.  

### HMAC
HMAC,即哈希消息验证码,是对密文和密钥的一个信息摘要,通过校验HMAC可以同时确定密钥和密文是否正确,未来还将支持MD5等其他哈希算法.  
**HMAC的哈希模式**  
  - 0:sha1
  - 1:md5
  - 2:sha256

### AES加密模式
早期版本的加密方式为确定性加密,安全性较差,易遭到选择明文攻击.此次更新引入了五种不同的AES加密模式:  
  - 0:电子密码本ECB  
  - 1:密码块链CBC  
  - 2:计数器模式CTR  
  - 3:密文反馈CFB  
  - 4:输出反馈OFB  

进行加解密时可输入相应的序号(命令行参数中的mode)以选择相应的加密方式,若输入不在0-4之间,择默认选择0号ECB模式(个人不建议选择0号).  
以上五种模式除ECB外均为非确定性加密,需要初始向量IV.在命令行模式中可以手动输入字符串以生成IV(不建议重复使用相同的字符串,会造成安全风险).在命令行参数模式下系统会自动生成随机的IV.  

### pcks7填充  
在加密信息尾部处理时,经常会遇到填充问题,此前采用的0填充需另行记录尾部字节数(即tail),较为繁琐也不安全.更新后的加密采用了较为流行的pcks7填充方式,使加解密更简洁,安全性更高.  

## 更新日志

*v1.1 新增:以base64编码输入密码,并重构了部分代码.*  
*v1.2 新增:git actions用于提交自动测试.*  
*v1.3 新增:删除部分冗余代码并重构部分代码以提高效率.*  
*v1.4 新增:改变部分代码结构以提高效率.*
*v1.5 新增:重写buffer部分,为未来支持多线程提供条件.*  
*v1.6 新增:重写部分核心函数,小幅提高运行效率.(1.6.1 重写makefile文件和部分核心代码)*  
*v1.7 新增:修复了有关IO缓冲区的bug,大幅减小了运行时的内存(小于50MB).并添加部分注释.(1.7.1 1.7.2 重写核心函数以提高运行效率)*  
*v1.8 新增:更改文件结构和makefile文件,提高核心代码运行效率.*  
*v1.9 新增:增加了加密文件验证的功能.(1.9.1 git actions中增加速度测试代码)*  
*v1.10 新增:改变为c++语言实现.(1.10.1 改变部分文件结构 1.10.2 重构部分代码以提高执行效率)*  
*v1.11 新增:重写IO缓冲区以减小内存占用.*  
*v2.0 新增:支持多线程模式.(2.0.1 改变并发中同步结构)*  
*v2.1 新增:改变加密文件头的格式.(2.1.1 2.1.2 改变多线程实现以支持多平台)*  
*v2.2 新增:部分函数改用类进行包装,重写多线程同步逻辑.(2.2.1 2.2.2 重构部分代码)*  
*v2.3 新增:增加随机缓冲哈希,使得在同文件同密钥情况下加密仍能得到不同的加密文件,提高了安全性.*  
*v2.4 新增:修复了windows环境下多线程同步失败的bug.*   
*v2.5 新增:修复了与RBH相关的bug.(2.5.1 改变文件结构)*  
*v2.6 新增:采用cmake自动构建和ctest自动测试.(2.6.1 增加自动速度测试版本查看并修复已知bug 2.6.2 2.6.3 修改文件结构)*  
*v2.7 新增:改变部分功能的实现和文件结构(2.7.1 更改部分文件以兼容visual stdio 2.7.2 改变sha1哈希类的实现).*  
*v2.8 新增:修改并发函数和哈希函数(2.8.1 2.8.2 2.8.3 更改部分函数实现).*  
*v2.9 新增:使用HMAC-SHA1进行文件验证.*  
*v3.0 新增:可选用不同的加密模式,采用pcks7进行填充,增加大量测试用例以测试核心组件的正确性,修复部分bug.(3.0.1 改变哈希部分结构,用以支持多种哈希模式. 3.0.2 优化文件结构)*  
*v3.1 新增:采用标准化的命令行解析函数来获取参数，优化文件结构(3.1.1 增加-n选项 3.1.2 重构部分代码).*  
*v3.2 新增:修复已知bug,更改文件头结构以便未来兼容不同哈希类型的hmac.*  
*V3.3 新增:可选择使用md5的hmac(3.3.1 重构部分代码并添加注释,重写时间测量逻辑,增加cmake编译选项).*
*V3.4 新增:采用多种设计模式进行代码优化(3.4.1优化部分处理过程输出 3.4.2 使用设计模式进行进一步优化).*
*V3.5 新增:修复已知bug,更新输出界面,采用统一格式输出结果.*
*V3.6 新增:更改多线程实现,提高效率.可选择使用sha256的hmac(v3.6.1修复部分bug, v3.6.2改变部分函数实现,修复已知bug v3.6.3更改核心接口函数 v3.6.4更改默认输出文件路径 v3.6.5windows兼容).*  
*V3.7 新增:适配windowsGUI,添加哈希进度显示,增加密钥输入审查(v3.7.1修复部分bug,改进验证流程 v3.7.2修改缓冲区更新代码 v3.7.3修改加载进度显示逻辑 v3.7.4修改部分输出描述)*
*V4.0 新增:采用AES-NI硬件指令实现AES加解密,大幅提升加解密速度;修复多线程下各线程共用同一IV导致的密钥流重用安全问题,改为每线程使用独立IV;修复部分缓冲区边界越界访问、对齐加载、输入溢出等问题.*  
*V4.0.1 修复:修复SHA1/MD5/SHA256在消息末尾块为56-63字节时长度字段被填充块污染导致摘要错误的bug;为Aesmode/Hashmaster/buffer64/AbsResultPrint补充虚析构函数;修复测试比较函数对二进制数据的strcmp误判;修复hmac::getres中逗号运算符导致的h1/h2/hashmaster内存泄漏;修复runcrypt构造函数在settings初始化前读取其成员的问题;清除全部编译警告;新增NIST/标准向量测试、边界尺寸往返测试、线程数变化测试、失败路径测试、CLI错误路径测试、交互式E2E测试.*
*V4.0.2 新增:文件头offset 47记录加密线程数(自描述,旧格式回退4线程,不同线程数构建可互相解密);多线程改为"读线程--工作线程--写线程"三级流水线,读写I/O可重叠;新增跨线程格式兼容测试.*
*V4.0.3 优化:加密时HMAC改为写线程导出密文同步增量计算(init_hash/feed_hash/final_hash),消除加密后回读密文的一遍I/O,加密由三遍I/O降为两遍.*
*V4.0.4 优化:SHA1/SHA256改用SHA-NI硬件指令(sha_ni.cpp, 移植自Intel ipsec-mb参考实现),软件SHA1 ~210MB/s→~1.8GB/s、SHA256 ~130MB/s→~1.6GB/s;native文件系统加密吞吐由~100MB/s提升至~155MB/s.*
*V4.0.5 新增:支持原生Windows(MSVC)构建运行——内置POSIX getopt_long移植(getopt_port),CMake区分MSVC/GCC编译选项(MSVC加/utf-8),源码/测试文件二进制模式与filesystem跨平台修正.*
*V4.1.0 优化:支持新优化后的WCGP(即WindowsGUI)v1.0,修改了文件头验证逻辑以增强健壮性*