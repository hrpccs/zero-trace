# 项目结构文档

## 一.项目总体结构
* [CMakeLists.txt]()
* [doc(dir)]()
    * [development_report.md]()
    * [env&vsock.md]()
    * [hookpoint.md]()
    * [structure.md]()
* [envtest(dir)]()
    * [build.sh]()
    * [client.cpp]()
    * [mesgtype.cpp]()
    * [mesgtype.h]()
    * [mythread.cpp]()
    * [mythreads.h]()
    * [README.md]()
    * [server.cpp]()
    * [testcase.h]()
    * [timesync.cpp]()
    * [timesync.h]()
    * [vsockutils.cpp]()
    * [vsockutils.h]()
* [gallery(dir)]()
* [LICENSE]()
* [README.md]()
* [runbenchmark(dir)]()
    * [benchmark(dir)]()
        * [example.txt]()
        * [install_sysbench_ubuntu.sh]()
    * [launch_benchmark.py]()
* [src(dir)]()
    * [CMakeLists.txt]()
    * [include(dir)]()
        * [basic_types.h]()
        * [event_defs.h]()
        * [hook_point.h]()
        * [iotracer.h]()
        * [log.h]()
        * [mesgtype.h]()
        * [system_macro.h]()
        * [timesync.h]()
        * [utils.h]()
        * [vmlinux.h]()
        * [vsockutils.h]()
    * [iotrace.bpf.c]()
    * [iotracer.cpp]()
    * [log.cpp]()
    * [main.cpp]()
    * [mesgtype.cpp]()
    * [qemu_uprobe.bpf.c]()
    * [timesync.cpp]()
    * [utils.cpp]()
    * [vsockutils.cpp]()

## 二.文件,目录功能描述

### [CMakeLists.txt](../CMakeLists.txt)
顶层的CMakeList文件,用来帮助编译的
### [doc(dir)](.)
存放各种文档的目录
#### [development_report.md](./development_report.md)
开发文档.其内部介绍了本项目的开发动机,实现思路,一些难点和解决方案,性能分析方法与结果等
#### [env&vsock.md](./env&vsock.md)
环境配置文档,其介绍了如何配置eBPF(libbpf)环境,如何安装QEMU,如何使得QEMU连接外部网络,如何使用和测试vsock
附录中还介绍了如果希望在其他程序中使用我们的vsock框架,应该如何使用
#### [hookpoint.md](./hookpoint.md)
介绍了eBPF中block layer的一些关键挂载点,便于开发
#### [structure.md](./structure.md)
也即本文档,介绍每个文件的大致作用.
### [envtest(dir)](../envtest/)
一个测试文件夹,其中的测试程序可以测试你的QEMU,vsock和cereal能否正常运行
建议正式运行整个追踪框架前,先运行本测试,排除vsock通信和cereal安装的问题
测试框架更具体的介绍可以参考[这里](./env&vsock.md#三环境可用性测试)
其用法可以参考[这里](../envtest/README.md)
本文件夹内测试程序也构成了vsock通信框架的一个简单示例,可以仿照该示例,进行vsock通信应用的开发
#### [build.sh](../envtest/build.sh)
测试程序的编译脚本
#### [client.cpp](../envtest/client.cpp)
测试程序的client(guest)端主函数所在文件,负责启动客户端的模拟tracing线程和vsock传输线程.
#### [mesgtype.cpp](../envtest/mesgtype.cpp)
为各种需要传输的类生成序列化/反序列化helper函数.
#### [mesgtype.h](../envtest/mesgtype.h)
本文件用来注册各种需要传输的类,并为它们生成函数原型,初始化helper,生成类型标识等
#### [mythread.cpp](../envtest/mythread.cpp),[mythreads.h](../envtest/mythread.h)
定义并实现三个host端线程所需的函数和两个guest端线程所需的函数
#### [README.md](../envtest/README.md)
简单介绍这一测试程序
#### [server.cpp](../envtest/server.cpp)
测试程序的server(host)端主函数所在文件,负责启动服务端的模拟tracing线程,vsock传输线程和可视化线程.
#### [testcase.h](../envtest/testcase.h)
定义了测试用的消息类型
#### [timesync.cpp](../envtest/timesync.cpp),[timesync.h](../envtest/timesync.h)
定义了时钟同步消息类型
#### [vsockutils.cpp](../envtest/vsockutils.cpp)[vsockutils.h](../envtest/vsockutils.h)
通信框架最重要的部分,定义了客户端和服务器Engine,可以自动化地完成连接和消息传输
### [gallery(dir)](../gallery/)
所有`.md`文档用到的图片都在其中
### [LICENSE](../LICENSE)
开源协议,本项目遵循GPL2.0协议,他人可以依据该协议将本项目代码用于自己的开源项目中
### [README.md](../README.md)
本项目的总体介绍文档
### [runbenchmark(dir)](../runbenchmark/)
一个性能测试框架,可以测试本Tracing框架的性能
#### [benchmark(dir)](../runbenchmark/benchmark/)
待完善
##### [example.txt](../runbenchmark/benchmark/example.txt)
一个性能测试的例子
##### [install_sysbench_ubuntu.sh](../runbenchmark/benchmark/install_sysbench_ubuntu.sh)
性能测试软件sysbench的安装脚本
#### [launch_benchmark.py](../runbenchmark/launch_benchmark.py)
运行测试程序的python脚本
### [src(dir)](../src/)
本项目的关键部分,里面包含了最重要的Tracing框架的源代码
#### [CMakeLists.txt](../src/CMakeLists.txt)
内层CMake文件
#### [include(dir)]()
##### [basic_types.h]()
##### [event_defs.h]()
##### [hook_point.h]()
##### [iotracer.h]()
##### [log.h]()
##### [mesgtype.h]()
##### [system_macro.h]()
##### [timesync.h]()
##### [utils.h]()
##### [vmlinux.h]()
##### [vsockutils.h]()
#### [iotrace.bpf.c]()
#### [iotracer.cpp]()
#### [log.cpp]()
#### [main.cpp]()
#### [mesgtype.cpp]()
#### [qemu_uprobe.bpf.c]()
#### [timesync.cpp]()
#### [utils.cpp]()
#### [vsockutils.cpp]()