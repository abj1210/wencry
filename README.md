# 数据加密解密程序

作者：闻嘉迅  
日期：2026.8.12 (最后修改)  
版本：v4.2.1

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
先检查魔数、加密/哈希模式与线程数等文件头结构,确定为正确加密后的文件  
提取IV与文件头存储的HMAC  
读取密文的同时由独立HASH线程增量计算HMAC(解密融合,不再单独整读一遍密文验证),AES128解密并写出明文  
解密完成后再比对HMAC,不匹配则删除输出文件并报错  

**验证**  
与解密共用同一读+HASH流水线,仅计算并比对HMAC,不做AES解密与写出

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
  - main.cpp:程序入口(交互式/命令行两种模式)
  - config.h.in:编译配置模板(生成config.h)
  - **valget:命令行参数解析文件夹**
    - getval.h:参数获取接口声明
    - getopts.cpp:命令行选项解析(get_v_opt)
    - getval1.cpp:交互式用户输入解析(get_v_mod1)
    - getopt_port.cpp/h:POSIX getopt_long 移植(Windows MSVC 使用)
  - **valhelper:参数包与辅助工具文件夹**
    - valhelper.h/cpp:vpak_t参数包、base64密钥校验、随机密钥、模式映射
    - information.cpp:版本/帮助信息与模式名查询(WencryInformation)
    - base64.h/cpp:base64编码/解码与合法性校验
  - **kernel:加解密核心文件夹**
    - cry.h/cry.cpp:整体加解密流程接口(runcrypt/execute_*,check_header,file_path)
    - fheader.h/fheader.cpp:加密文件头生成/验证、增量HMAC计算、结果打印
    - **multi_aes:多线程AES加解密文件夹**
      - multicry.h/cpp:多线程调度器(multicry_master,按模式启动读/HASH/AES/写线程)
      - multi_buffergroup.h/cpp:统一读--HASH--AES--写流水线缓冲组(加密/解密/验证三模式)
      - **aes:AES加解密实现文件夹**
        - aesmode.h/cpp:五种模式(ECB/CBC/CTR/CFB/OFB)加密器
        - aes_ni.h/cpp:基于AES-NI指令的AES-128密钥扩展与单块变换
    - **hash:哈希函数文件夹**
      - hashmaster.h/cpp:哈希抽象基类/工厂与字符串哈希、增量哈希接口
      - sha1.cpp、md5.cpp、sha256.cpp:软件实现
      - sha_ni.h/cpp:SHA-NI硬件加速SHA1/SHA256
  - **test:测试文件夹**
    - testutil.h/cpp:测试工具(临时文件名/模式文件/hex解析)
    - test.h/cpp:复用runcrypt的往返与速度测试函数(exec/cmp_file/makeFullTest等)
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
    - testvectors.cpp:NIST/标准向量测试(AES各模式、FIPS-197、哈希填充边界、HMAC参考向量、CTR进位、大缓冲哈希)
    - testboundary.cpp:边界尺寸往返、线程数变化、文件头布局、失败路径、解密/验证返回值与异常、CLI错误路径测试
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

> **MSB8070 工具集缺失**:若机器装有多个 VS 实例,CMake 可能把生成器实例选到缺少目标 MSVC 工具集的那个(报错形如`找不到 MSVC 工具集版本"14.50.35717"`)。此时用 `-DCMAKE_GENERATOR_INSTANCE` 显式指定装有该工具集的实例即可,例如:
>    ```bat
>    cmake -G "Visual Studio 18 2026" -A x64 -S . -B build_vs -DBUILD_TEST=OFF -DCMAKE_GENERATOR_INSTANCE="C:/Program Files (x86)/Microsoft Visual Studio/18/BuildTools"
>    cmake --build build_vs --config Release
>    ```


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
加解密/验证采用统一"读线程--HASH线程--工作线程--写线程"流水线:读线程按顺序`fread`装载数据块,独立的HASH线程按块序增量计算HMAC,多个工作线程就地AES加解密,写线程按序号`fwrite`导出,各段可重叠,不再由单一维护线程串行承担全部文件I/O.  
加密时HASH线程读AES后的密文;解密/验证时HASH线程先于AES读密文(密文被就地覆盖前),解密因此融合了HMAC验证,无需再单独整读一遍.  
每个工作线程有唯一`id`,chunk k固定由线程`k%N`处理,以保持各线程AES的IV链一致.  
详细协作逻辑见`multi_buffergroup.cpp`注释.

- **冗余缓冲对工作线程并发的影响**  
`cry.h`中`REDUNDANCY_BUFFER`(默认2)使缓冲总数 = 线程数 + 冗余(默认4+2=6个16MB缓冲),即缓冲数大于工作线程数.其对并发的影响:
  - **加深流水线**:读线程可把多个块预读到不同缓冲,工作线程不至于因读线程忙而空等;流水线在途深度 = 缓冲总数,最多 6×16MB=96MB 数据同时处于读/HASH/AES/写各段。
  - **工作线程名下出现多个在途块**:块 k 装入 buf[k%size]、由线程 k%total_threads 处理,因 size>total_threads,同一工作线程名下会同时存在多个块(如4线程6缓冲时,线程0拥有块0、4,对应缓冲0、4)。工作线程须按块序(`thread_seq_tag`)逐个排空名下各块,才能维持链式模式(如CBC/CTR)的IV链连续——这也是"收尾排空"逻辑存在的根本原因。
  - **有界背压**:读线程受"目标缓冲须为EMPTY"限制,冗余再多也不会无界预读,内存上界 = 缓冲数×16MB。
  - **HASH线程按块号顺序消费**:HASH线程独立按块序读密文喂HMAC,与工作线程处理顺序解耦,保证HMAC严格按文件序。
  - **调节权衡**:增大`REDUNDANCY_BUFFER`可加深流水线、提升I/O与计算重叠(尤其慢盘/高延迟I/O),但内存线性增加(每块16MB);减小则更省内存、流水线更浅,线程密集时易因等待缓冲而停顿。默认4+2在吞吐与内存(<90MB)间平衡。

## WSL运行提速建议

- `/mnt/d`等9p挂载盘I/O较慢,可在`/etc/wsl.conf`的`[automount]`节开启缓存以显著提升文件读写速度,例如:
  ```ini
  [automount]
  enabled = true
  options = "metadata,umask=22,fmask=11,cache=mmap"
  ```
- 处理大文件时,将数据放在WSL原生ext4(如`/tmp`或`~/`)上再加密,通常比`/mnt/d`快数倍.
- 实测单次加解密的速度上限主要受文件I/O总吞吐限制(加密需读明文+写密文共两遍;解密HMAC随读取融合,读密文+写明文共两遍),I/O越快吞吐越高.

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
*V4.2.0 接口:execute_encrypt/execute_decrypt/execute_verify 改为异常接口——加密遇到无效文件抛 std::string("Invalid File");解密/验证成功返回 (htype<<8)|ctype(高8位哈希模式、低8位加密模式),失败抛 std::string 错误信息(坏魔数/文件过短/密钥或文件不完整/模式不匹配).*  
*V4.2.0 测试:测试迁移至新版接口,新增解密/验证返回值(各ctype×htype组合)与异常消息测试(空文件句柄、坏魔数、损坏数据、错误密钥、模式字节非法、文件过短);修复exec对NULL参数包/版本/帮助路径的布尔返回值反转问题.*  
*V4.2.0 文档:为valhelper、valget、main、test等模块补充函数与类注释,更新README文件结构与更新日志.*  
*V4.2.1 流水线:加密/解密/验证三模式统一到"读--HASH--AES--写"多线程流水线——新增独立HASH线程按块序增量计算HMAC;解密融合HMAC验证(消除单独整读密文验HMAC的一遍I/O,由3遍降为2遍),失败时删除输出文件(从FILE*反推路径,Windows/POSIX);验证(-v)复用同一读+HASH流水线,不做AES与写出.*  
*V4.2.1 清理:删除filebuffer64/hashbuffer(64字节块文件哈希缓冲)与Hashmaster::getFileHash,统一改用增量哈希;hmac::getres改用增量分块计算(测试兼容).*  
*V4.2.1 性能:原生Windows缓存态吞吐——加密~1.26GB/s、解密~1.0-1.6GB/s、验证~1.45-1.7GB/s(较融合前显著提升).*  
*V4.2.1 构建:修复VS生成器多实例环境下MSB8070工具集缺失(CMake默认实例缺目标MSVC工具集)——README补充用 -DCMAKE_GENERATOR_INSTANCE 显式指定装有该工具集的VS实例.*