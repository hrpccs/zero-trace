# 简介
本框架是一个基于eBPF的追踪框架,目的是在低开销下对一些内核路径进行追踪和性能分析
这个项目的灵感来自于[oscomp-proj133](https://github.com/oscomp/proj133-ebpf-tracing-framework).

我们已经实现了对Linux的I/O调用栈路径的追踪,包括文件系统层次和Block层次.这一部分被我们称为"IO wpTracer" (IO whole path tracer).

可以**查看我们的[开发文档](doc/development_report.md)**来了解我们的工作
也可以访问我们的[Github页面](https://github.com/hrpccs/zero-trace)

![arch](gallery/arch.png)

本项目基于eBPF 和 Libbpf+CO-RE.如果要编译这个项目,需要
- 支持Libbpf+CO-RE 
- 确保你的内核支持BTF

## 环境配置

请参考[环境配置文档](./doc/env.md)

## 编译运行

```bash
$ cmake -S . -B build -DWITH_GRAFANA=ON/OFF
$ cd build 
$ make 
$ sudo ./iotracer  -w 1.0 -o log -T 2 -n  "task name to trace" e.g. you can use sysbench located at runbenchmark dir.
```


# Introduction
We are currently developing a tracing framework based on eBPF, which aims to trace the entire path of system calls under low overhead. This project was inspired by [oscomp-proj133](https://github.com/oscomp/proj133-ebpf-tracing-framework).

We have completed a part of the framework. It is now able to trace the entire path of the read/write syscall within the Linux I/O stack, including the FS layer and Block layer. And we call this part of the framework "IO wpTracer" (IO whole path tracer).

**You can check our [development report](doc/development_report.md)**, which describes our work.
And you can also visit our [GitHub repository](https://github.com/hrpccs/zero-trace).


![arch](gallery/arch.png)



The project is based on eBPF and Libbpf+CO-RE. To compile this project, you'll need to:
- Enable Libbpf+CO-RE 
- Make sure your linux kernel supports eBPF and provide BTF.

### Dependencies: libbpf + CO-RE

See [Environment Setting Document](./doc/env.md)


### Build and Run our demo

```bash
$ cmake -S . -B build -DWITH_GRAFANA=ON/OFF
$ cd build 
$ make 
$ sudo ./iotracer  -w 1.0 -o log -T 2 -n  "task name to trace" e.g. you can use sysbench located at runbenchmark dir.
```



