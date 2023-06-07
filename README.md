# Introduction

We are currently developing a tracing framework based on eBPF, which aims to trace the entire system call path within the Linux kernel with low overhead. This project was inspired by [oscomp-proj133](https://github.com/oscomp/proj133-ebpf-tracing-framework).

We have developed a part of the job. it is able to trace the entire path that the read/wrtie syscall run through within linux I/O stack , including FS layer and Block layer. 

And we call this part of job `IO wpTracer (IO whole path tracer)`

**You can check our [development report](doc/development_report.md)**. The report describes our job.

And you can also visit our GitHub repository https://github.com/hrpccs/zero-trace.

![arch](gallery/arch.png)



We develop this project  application with C/C++ and eBPF program with libbpf with CO-RE

To compile this project, you need libbpf with CO-RE and a linux kernel that supports eBPF and provide BTF

### Dependencies: libbpf with CO-RE

To use BTF and CO-RE, `CONFIG_DEBUG_INFO_BTF=y` and `CONFIG_DEBUG_INFO_BTF_MODULES=y` need to be enabled. If you don't want to rebuild the kernel, the following distos have enabled those options by default:

- Ubuntu 20.10+
- Fedora 31+
- RHEL 8.2+
- Debian 11+

And to build bpf applications, the following development tools should also be installed:

Note: we develop ebpf user space program in C++ and we use bpftool to generate skeleton. We use the C++ feature which only is provided since bpftool v6.8, [check this](https://github.com/libbpf/bpftool/releases/tag/v6.8.0)

```
# Ubuntu
sudo apt-get install -y make clang llvm libelf-dev 

# RHEL
sudo yum install -y make clang llvm elfutils-libelf-devel 

# WSL2 
# bpftool which shall be compiled and installed from kernel souce code provided by Microsoft
# source code
https://github.com/microsoft/WSL2-Linux-Kernel 
# can reffer to link below for instruction
https://gist.github.com/MarioHewardt/5759641727aae880b29c8f715ba4d30f
```

### Build and Run our demo

```bash
$ cmake -S src -B build
$ cd build 
$ make 
$ sudo ./iotracer  -w 1.0 -o log -T 2 -n  "task name to trace" e.g. you can use sysbench located at runbenchmark dir.
```



