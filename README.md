# 数据加密解密程序

作者：闻嘉迅  
日期：2023.11.13 (最后修改)  
版本：v1.6.1  

**处理速度可达28-32MB/s**

## 加密原理

对于目标文件进行AES128加密  
对加密后的信息和密钥进行sha1哈希操作  
得到最终的加密文件  

## 文件结构

- include:头文件  
    - util:通用的结构体和宏  
        - buffer.h:IO缓冲区的头文件  
        - def.h:宏定义  
        - struct.h:结构体  
    - util.h:包含了util文件夹下的所有头文件  
    - getval.h:获取操作参数相关的头文件
    - aes.h:AES加解密相关的头文件
    - cry.h:加解密流程相关的头文件
    - sha1.h:进行sha1哈希相关的头文件

- src:源代码
    - aesd.c:负责AES解密的各流程
    - aese.c:负责AES加密的各流程  
    - base64.c:负责进行base64的编码和解码  
    - buffer.c:实现IO缓冲区  
    - cry.c:负责整体加解密流程
    - main.c:主函数
    - sha1.c:负责产生sha1哈希的流程
    - tab.c:生成各种数表
- test:测试
    - test.c:测试代码
    - testfile.txt t2.txt:测试文件

## 使用方法

使用`make wencry`命令进行编译  
使用`make test_once`命令进行自动测试  
使用`make gprof`命令进行性能分析(此时应在F变量中加入`-pg`选项)

### 加密

直接使用`./wencry`命令，按提示进行操作

使用`./wencry -e [fin] [code] [fout]`命令进行加密  
其中 -e 代表加密选项 fin 为输入文件的路径 code 为ase64编码后的16字节16进制数(编码后共24位),若输入G则为程序生成 fout 为输出文件名，缺省为 fin 值.  

加密完毕后会生成名为 [fout].wenc 的加密文件.

### 解密

直接使用`./wencry`命令,按提示进行操作

使用`./wencry -d [fin] [code] [fout]`命令进行加密  
其中 -e 代表加密选项 fin 为输入文件的路径 code 为base64编码后的16字节16进制数(编码后共24位), fout 为输出文件名,缺省为 [fin].wdec .

解密完毕后若无误则会生成名为 fout 的还原文件.


*v1.1 新增:以base64编码输入密码,并重构了部分代码.*  
*v1.2 新增:git actions用于提交自动测试.*  
*v1.3 新增:删除部分冗余代码并重构部分代码以提高效率.*  
*v1.4 新增:改变部分代码结构以提高效率.*
*v1.5 新增:重写buffer部分,为未来支持多线程提供条件.*  
*v1.6 新增:重写部分核心函数,小幅提高运行效率.(1.6.1 重写makefile文件和部分核心代码)*