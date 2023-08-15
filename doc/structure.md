# 项目结构文档

## 一.项目总体结构
- [项目结构文档](#项目结构文档)
  - [一.项目总体结构](#一项目总体结构)
  - [二.文件,目录功能描述](#二文件目录功能描述)
    - [CMakeLists.txt](#cmakeliststxt)
    - [doc(dir)](#docdir)
      - [初赛开发文档.md](#初赛开发文档md)
      - [复赛开发文档.md](#复赛开发文档md)
      - [env.md](#envmd)
      - [vsock\_use.md](#vsock_usemd)
      - [functional\_test.md](#functional_testmd)
      - [performance\_test.md](#performance_testmd)
      - [io\_hookpoint.md](#io_hookpointmd)
      - [structure.md](#structuremd)
    - [envtest(dir)](#envtestdir)
      - [build.sh](#buildsh)
      - [client.cpp](#clientcpp)
      - [mesgtype.cpp](#mesgtypecpp)
      - [mesgtype.h](#mesgtypeh)
      - [mythread.cpp,mythreads.h](#mythreadcppmythreadsh)
      - [README.md](#readmemd)
      - [server.cpp](#servercpp)
      - [testcase.h](#testcaseh)
      - [timesync.cpp,timesync.h](#timesynccpptimesynch)
      - [vsockutils.cppvsockutils.h](#vsockutilscppvsockutilsh)
    - [gallery(dir)](#gallerydir)
    - [grafana(dir)](#grafanadir)
      - [docker(dir)](#dockerdir)
        - [docker-compose.yaml](#docker-composeyaml)
        - [otel-collector.yaml](#otel-collectoryaml)
      - [shared(dir)](#shareddir)
        - [grafana-datasources.yaml](#grafana-datasourcesyaml)
        - [tempo.yaml](#tempoyaml)
    - [LICENSE](#license)
    - [README.md](#readmemd-1)
    - [runbenchmark(dir)](#runbenchmarkdir)
      - [benchmark(dir)](#benchmarkdir)
        - [example.txt](#exampletxt)
        - [install\_sysbench\_ubuntu.sh](#install_sysbench_ubuntush)
      - [launch\_benchmark.py](#launch_benchmarkpy)
    - [src(dir)](#srcdir)
      - [CMakeLists.txt](#cmakeliststxt-1)
      - [include(dir)](#includedir)
        - [basic\_types.h](#basic_typesh)
        - [event\_defs.h](#event_defsh)
        - [hook\_point.h](#hook_pointh)
        - [iotracer.h](#iotracerh)
        - [log.h](#logh)
        - [mesgtype.h](#mesgtypeh-1)
        - [system\_macro.h](#system_macroh)
        - [timesync.h](#timesynch)
        - [utils.h](#utilsh)
        - [vmlinux.h](#vmlinuxh)
        - [vsockutils.h](#vsockutilsh)
      - [iotrace.bpf.c](#iotracebpfc)
      - [iotracer.cpp](#iotracercpp)
      - [log.cpp](#logcpp)
      - [main.cpp](#maincpp)
      - [mesgtype.cpp](#mesgtypecpp-1)
      - [qemu\_uprobe.bpf.c](#qemu_uprobebpfc)
      - [timesync.cpp](#timesynccpp)
      - [utils.cpp](#utilscpp)
      - [vsockutils.cpp](#vsockutilscpp)

## 二.文件,目录功能描述
### [CMakeLists.txt](../CMakeLists.txt)
顶层的CMakeList文件,用来帮助编译的
### [doc(dir)](.)
存放各种文档的目录
#### [初赛开发文档.md](./初赛开发文档.md)
初赛期间形成的开发文档
初赛阶段主要是对于磁盘读写的VFS,Block,Driver层实现追踪,并且能处理Block层Split和Merge操作
但是性能相对较差
#### [复赛开发文档.md](./复赛开发文档.md)
复赛期间形成的开发文档
主要包括Grafana开发,QEMU配置,vsock通信框架开发,通过过滤机制和合理的挂载点实现的性能优化,virtio的Tracing
#### [env.md](./env.md)
环境配置文档,其介绍了如何配置eBPF(libbpf)环境,如何安装QEMU,如何使得QEMU连接外部网络,如何使用和测试vsock
#### [vsock_use.md](./vsock_use.md)
介绍了如果希望在其他程序中使用我们的vsock框架,应该如何使用
该框架已经经过检验,确保可靠
#### [functional_test.md](./functional_test.md)
功能测试文档,证明我们已经实现了上述功能
#### [performance_test.md](./performance_test.md)
性能测试文档,证明我们已经达到了较好的性能
#### [io_hookpoint.md](./hookpoint.md)
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
为测试框架各种需要传输的类生成序列化/反序列化helper函数.
#### [mesgtype.h](../envtest/mesgtype.h)
本文件用来为测试框架注册各种需要传输的类,并为它们生成函数原型,初始化helper,生成类型标识等
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
### [grafana(dir)](../grafana/)
我们使用Grafana可视化框架进行可视化和监控.
使用Grafana可用轻松地对我们抓取到的Tracing信息进行处理,生成直观的图像,并可以进行一些分析
#### [docker(dir)](../grafana/docker/)
我们用docker运行与Grafana有关的组件.
##### [docker-compose.yaml](../grafana/docker/docker-compose.yaml)
大家喜闻乐见的docker文件,这涉及到三个容器,也即Grafana,Tempo(数据库)和otel-collector(收集数据)
##### [otel-collector.yaml](../grafana/docker/otel-collector.yaml)
otel-collector的一些配置
#### [shared(dir)](../grafana/shared/)
一些其他的配置文件,可能被其他软件读取
##### [grafana-datasources.yaml](../grafana/shared/grafana-datasources.yaml)
定义了Grafana的数据源
##### [tempo.yaml](../grafana/shared/tempo.yaml)
设置了Tempo的种种参数的配置文件
### [LICENSE](../LICENSE)
开源协议,本项目遵循GPL2.0协议,他人可以依据该协议将本项目代码用于自己的开源项目中
### [README.md](../README.md)
本项目的总体介绍文档
### [runbenchmark(dir)](../runbenchmark/)
一个性能测试框架,可以测试本Tracing框架的性能
#### [benchmark(dir)](../runbenchmark/benchmark/)
可以用 sysbench 进行 io benchmark
##### [example.txt](../runbenchmark/benchmark/example.txt)
一个性能测试的例子
##### [install_sysbench_ubuntu.sh](../runbenchmark/benchmark/install_sysbench_ubuntu.sh)
性能测试软件sysbench的安装脚本
#### [launch_benchmark.py](../runbenchmark/launch_benchmark.py)
运行测试程序的python脚本
### [src(dir)](../src/)
本项目的关键部分,里面包含了最重要的Tracing框架的源代码
#### [CMakeLists.txt](../src/CMakeLists.txt)
内层CMake文件,可以帮助生成Makefile
#### [include(dir)](../src/include/)
各种头文件都在这里
##### [basic_types.h](../src/include/basic_types.h)
Tracing所需要的一些基本的数据结构,包括了处理后的事件,内存池和请求.
##### [event_defs.h](../src/include/event_defs.h)
定义了eBPF直接抓到的事件结构和过滤参数
##### [hook_point.h](../src/include/hook_point.h)
定义了各个挂载点和I/O请求各个层次的类型
##### [iotracer.h](../src/include/iotracer.h)
定义了 IOTracer 这个类以及一些重要的功能
##### [log.h](../src/include/log.h)
将日志写到文件里的模块的头文件
##### [mesgtype.h](../src/mesgtype.cpp)
本文件用来为Tracing框架注册各种需要传输的类,并为它们生成函数原型,初始化helper,生成类型标识等.
* 与测试文件中[同名文件](../envtest/mesgtype.h)功能类似
##### [system_macro.h](../src/include/system_macro.h)
一些与系统指令有关的宏定义
##### [timesync.h](../src/include/timesync.h)
[同上](#timesynccpptimesynch)
##### [utils.h](../src/include/utils.h)
一些获取设备号,文件inode号,时间戳等信息的辅助函数的原型
##### [vmlinux.h](../src/include/vmlinux.h)
自动生成的一个头文件,内核中的`bpftool`工具其中功能之一就是读取`vmlinux`文件并生成对应的`vmlinux.h`头文件。`vmlinux.h`会包含运行内核中所使用的每一个类型定义，因此该文件的比较大。
##### [vsockutils.h](../src/include/vsockutils.h)
[同上](#vsockutilscppvsockutilsh)
#### [iotrace.bpf.c](../src/iotrace.bpf.c)
与tracing相关的各个挂载点,除了QEMU之外
#### [iotracer.cpp](../src/iotracer.cpp)
IOTracer 处理内核 ringbuffer 事件时对不同事件的处理流程
#### [log.cpp](../src/log.cpp)
将日志写到文件里的模块
#### [main.cpp](../src/main.cpp)
整个程序的入口.解析命令行参数,启动对应的线程
#### [mesgtype.cpp]()
为Tracing框架各种需要传输的类生成序列化/反序列化helper函数.
* 与测试文件中[同名文件](../envtest/mesgtype.cpp)功能类似
#### [qemu_uprobe.bpf.c](../src/qemu_uprobe.bpf.c)
与tracing中QEMU相关的各个挂载点
#### [timesync.cpp](../src/timesync.cpp)
[同上](#timesynccpptimesynch)
#### [utils.cpp](../src/utils.cpp)
一些获取设备号,文件inode号,时间戳等信息的辅助函数的实现
#### [vsockutils.cpp](../src/vsockutils.cpp)
[同上](#vsockutilscppvsockutilsh)