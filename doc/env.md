

# 环境配置与vsock使用

- [一、eBPF环境配置](#一eBPF环境配置)
  - [WSL需要的特殊操作](#如果在wsl中使用还需要进行如下操作)
- [二、virtio之QEMU环境配置](#二virtio之QEMU环境配置)
  - [1、QEMU依赖的安装](#1QEMU依赖的安装)
  - [2、内层虚拟机(QEMU)安装](#2内层虚拟机(QEMU)安装)
  - [3、QEMU网络配置](#3QEMU网络配置)
  - [4、安装序列化库cereal](#4安装序列化库cereal)
- [三、环境可用性测试](#三环境可用性测试)
  - [1、一个简单的框架](#1一个简单的框架) 
  - [2、如何运行这个测试](#2如何运行这个测试) 
  - [3、将这个测试运用到tracing中](#3将这个测试运用到tracing中) 
- [附录A、如果想继续使用WSL,如何恢复使用?](#附录a如果想继续使用wsl如何恢复使用)
- [附录B、vsock通信框架使用方法](#附录Bvsock通信框架使用方法)
- [参考资料](#参考资料)

## 一、eBPF环境配置

先安装Ubuntu 22.04LTS(20.04也可以,但是要手动升级内核到5.15)

可以直接安装在物理机,也可以安装在VMWare中(针对VMWare可能存在一些问题,下面给出了解决方法)

注意内核被编译时,`CONFIG_DEBUG_INFO_BTF=y` and `CONFIG_DEBUG_INFO_BTF_MODULES=y`选项应该被设置.

* 就目前开发经验而言,这两个选项通常都默认被设置,比如以下的一些发行版

- Ubuntu 20.10+
- Fedora 31+
- RHEL 8.2+
- Debian 11+

部分安装操作需要比较快的Github访问,这需要自行解决.

本项目的eBPF开发是基于libbpf的.libbpf可以在编译阶段自动clone和编译,但是其依赖需要手动安装

```shell
sudo apt-get install -y make clang llvm libelf-dev linux-tools-$(uname -r)
```

在不使用virtio(QEMU)时,只需要安装一次.如果使用virtio,在QEMU内部也需要安装一次

**注意:** 我们在C++中开发eBPF用户态程序,用bpftool生成追踪框架的骨架.我们使用的部分特性要求bpftool版本不低于v6.8.[查看这里](https://github.com/libbpf/bpftool/releases/tag/v6.8.0).

### 如果在WSL中使用,还需要进行如下操作

```
# WSL2 
# bpftool which shall be compiled and installed from kernel souce code provided by Microsoft
# source code
https://github.com/microsoft/WSL2-Linux-Kernel 
# can reffer to link below for instruction
https://gist.github.com/MarioHewardt/5759641727aae880b29c8f715ba4d30f
```

## 二、virtio之QEMU环境配置

### 1、QEMU依赖的安装

```bash
sudo apt-get install git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev ninja-build
sudo apt-get install git-email
sudo apt-get install libaio-dev libbluetooth-dev libcapstone-dev libbrlapi-dev libbz2-dev
sudo apt-get install libcap-ng-dev libcurl4-gnutls-dev libgtk-3-dev
sudo apt-get install libibverbs-dev libjpeg8-dev libncurses5-dev libnuma-dev
sudo apt-get install librbd-dev librdmacm-dev
sudo apt-get install libsasl2-dev libsdl2-dev libseccomp-dev libsnappy-dev libssh-dev
sudo apt-get install libvde-dev libvdeplug-dev libvte-2.91-dev libxen-dev liblzo2-dev
sudo apt-get install valgrind xfslibs-dev 
sudo apt-get install libnfs-dev libiscsi-dev
```

安装QEMU(默认的就行),查看QEMU版本

```shell
sudo apt-get install qemu-system
qemu-img --help |grep version
qemu-img version 6.2.0 (Debian 1:6.2+dfsg-2ubuntu6.12)
```

使用VMWare的,可以用ssh连接进去,方便后续开发

```shell
sudo apt install openssh-server
sudo service ssh status
```

```bash
#启动ssh方法
systemctl start sshd
```

用ssh方法,借助VSCode,可以把镜像移动到虚拟机

### 2、内层虚拟机(QEMU)安装

创建镜像

```bash
qemu-img create -f qcow2 ubuntu22.img 20G
Formatting 'ubuntu22.img', fmt=qcow2 cluster_size=65536 extended_l2=off compression_type=zlib size=21474836480 lazy_refcounts=off refcount_bits=16
```

安装系统.我用的环境是:外层虚拟机4核,每个核心2个线程,8GB内存.内存虚拟机2核,3GB内存

* 这可以根据自己电脑的实际情况进行修改

```shell
qemu-system-x86_64 -enable-kvm -m 3G -smp 2 -boot once=d -drive file=./ubuntu22.img -cdrom ./ubuntu-22.04.2-desktop-amd64.iso -device ac97
```

**对于VMWare虚拟机,涉及嵌套虚拟化,记得在`虚拟机-设置-处理器-虚拟化引擎`开这个选项**

![image-20230730192650324](../gallery/environment&vsocks/image-20230730192650324.png)

**注意:开启后有可能开机会遇到这个问题**

![image-20230730192710187](../gallery/environment&vsocks/image-20230730192710187.png)![image-20230730192715574](../gallery/environment&vsocks/image-20230730192715574.png)

解决方法如下:

**注意这些操作会关掉HYPER-V导致WSL2进不去.**[如何恢复WSL2使用?](#附录A.如果想继续使用WSL,如何恢复使用?)

* 在任务栏搜索"服务",关闭画圈的服务

![image-20230730200356073](../gallery/environment&vsocks/image-20230730200356073.png)

* 进入有管理员权限的Powershell这样做

![image-20230730200559640](../gallery/environment&vsocks/image-20230730200559640.png)

解决问题以后就可以开始安装了

* 如果不想安装慢死就这样做,虽然总体上还是慢的

![image-20230730202320768](../gallery/environment&vsocks/image-20230730202320768.png)

### 3、QEMU网络配置

QEMU有多种网络模式,默认的是user模式,它可以连接到外部网络,但是并不能被外部网络看见,就不能ssh进去.所以我们需要使用其他网络模式,比如tap模式

先在宿主机创建一个网卡

**这一步在后面步骤全部完成以后,如果重启宿主机,效果可能会消失,所以重启后要重新输入以下三条命令**

且这个子网的编号是自己指定的,可以与此处不同

```shell
sudo ip tuntap add dev tap0 mode tap
sudo ip link set dev tap0 up
sudo ip address add dev tap0 192.168.2.128/24
```

![image-20230731124933888](../gallery/environment&vsocks/image-20230731124933888.png)

关闭QEMU并使用以下命令重新进入

```shell
sudo qemu-system-x86_64 -enable-kvm -m 3G -smp 2  -drive file=./ubuntu22.img -serial tcp::4444,server=on,wait=off -net nic -net tap,ifname=tap0,script=no,downscript=no -device vhost-vsock-pci,guest-cid=123 
```

但是会出现这个问题

```shell
qemu-system-x86_64: -net tap,ifname=tap0,script=no,downscript=no: could not configure /dev/net/tun (tap0): Operation not permitted
```

再这样做

```shell
sudo setcap CAP_NET_ADMIN=ep /usr/bin/qemu-system-x86_64
```

到这个时候QEMU内部还是连不上外面的,我们按照以下步骤,设置静态IP,配置路由表

* 首先再宿主机打开ip转发.输入以下命令

```bash
sudo gedit /etc/sysctl.conf
```

* 然后把加方框的一行的注释取消,**注意这一步需要重启才能生效**

![image-20230731155343493](../gallery/environment&vsocks/image-20230731155343493.png)

* 然后给客户机的网卡配置ip地址,**注意要和宿主机的tap0的ip地址在一个网段**
  * ens3是网卡的名字,可以`ifconfig`或者`ip addr`来看

```bash
ip addr add 192.168.2.114/24 dev ens3
sudo ip link set ens3 up #可能不需要,甚至可能这样一操作反而上一步白做了,这个时候重新做上一步
```

* 对客户机进行网络设置,配置静态IP
  * 注意Address填写前面给客户机分配的地址,Gateway填宿主机tap0的IP地址

![image-20230731160100373](../gallery/environment&vsocks/image-20230731160100373.png)

* 配置宿主机路由表,先输入以下命令查看路由表情况

```shell
route -n
```

* 如果有红框所示的内容,就不用管,否则输入以下命令

![image-20230731160513939](../gallery/environment&vsocks/image-20230731160513939.png)

```shell
sudo route add -net 192.168.2.0 netmask 255.255.255.0 dev tap0
```

* 开启宿主机的防火墙的相关功能,实现NAT,并持久化之.
  * 含义是,来自 192.168.2.0/24，且从 ens33 出去的包，要进行 NAT，同时会对返回的包进行 NAT

```shell
sudo iptables -t nat -A POSTROUTING -s 192.168.2.0/24 -o ens33 -j MASQUERADE
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

* 最后把用户机路由表看一下

![image-20230731162717346](../gallery/environment&vsocks/image-20230731162717346.png)

* 红框所示的内容多半是没有的,我们添加之

```shell
sudo route add default gw 192.168.2.128 dev ens3
```

* 这样就可以用了.然后就可以和上文一样配置ssh

### 4、安装序列化库cereal

`cereal`文件夹已经被放在`include`文件夹了,可以直接使用,无需额外操作

* 如果在其他项目中也想使用,可以将`cereal`文件夹移动到`/usr/include`文件夹中



## 三、环境可用性测试

### 1、一个简单的测试框架

![image-20230810231536426](../gallery/environment&vsocks/image-20230810231536426.png)

根据实际需要,我们的host端分为三个线程,guest端分为两个线程.划分如图所示

```c++
namespace HostThread
{
    void connect();
    void hook();
    void visualize();
};


namespace GuestThread
{
    void connect();
    void hook();
};
```



* `hook`是获取tracing信息以及传送给其他有关模块的函数,demo中使用每隔随机的时间,随机生成的办法.使用时肯定要根据需要进行修改
* connect函数提供连接的功能,负责创建连接.
  * host的connect还负责接收guest发过来的消息,分为对时钟的消息(调用`getDeltaHelper`)和把tracing信息放入相应队列(并发安全有保证)
  * guest的connect负责定期发起对时钟请求,把tracing信息取出,校正时间和发送到host.注意对时钟的时间限制可以通过修改`TIMEOUT`(单位ns)来指定
* visualize是可视化函数,执行可视化任务,本demo就直接输出到控制台了.且每次看远端和本地队列中哪一个时间戳早就先可视化哪一个
  * 注意,我们的messageexp只有一个时间戳.当把队列元素修改以后,如果是区间,可以比较结束时间

![image-20230810233517503](../gallery/environment&vsocks/image-20230810233517503.png)


### 2、如何运行这个测试

* 安装cereal.确保cereal文件夹被放在这个文件夹或者`/usr/include`中
* 进入`envtest`文件夹
* `sudo bash build.sh`编译.如果提示缺少依赖,请自行安装
* 用`scp`命令或者借助vscode等把可执行文件`client`移动到guest(QEMU)中
    * 如果是在虚拟机中,用vscode中转时经过了Windows物理机,移动到QEMU之后要`chmod +x ./client`恢复权限
* 在host(本机)运行server
* 在guest(QEMU)运行client
* 如果运行失败,很可能是QEMU启动的时候忘记添加vsock设备,请检查命令
* 如果运行成功会见到下图所示,左侧是单调时钟的时间戳(单位ns),右侧是随机字符串(长度不大于65)

[试一下你的vsock和cereal安装是否正常吧](../envtest/README.md)

![pic](../gallery/environment&vsocks/image-envtest.png)

### 3、将这个测试运用到tracing中

该测试框架虽然简陋,但是能够判断vsock和cereal的工作状态.且已经反映了Tracing中各个进程之间的通信方式
仅仅需要将其中"随机产生Tracing"的模块改为真实的eBPF最终模块,打印模块换成可视化模块(向Grafana发信息)
就可以实现Tracing功能了

## 附录A、如果想继续使用WSL,如何恢复使用?

我执行了以下三个操作,但是到底哪一步有用,难以验证.可能是其某一个非空子集实际起到作用

当然,这样执行以后嵌套虚拟化将无法使用.

* 第一个,开启windows功能`Hyper-V`

![image-20230804212305155](../gallery/environment&vsocks/image-20230804212305155.png)

* 第二个,在有管理员权限的Powershell输入以下命令(我猜没啥用)

```shell
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

* 第三个,在有管理员权限的Powershell输入以下命令(我感觉这一步作用比较大)

```shell
 bcdedit /set hypervisorlaunchtype Auto
```

## 附录B、vsock通信框架使用方法

可以查看[vsock通信框架使用](./vsock_use.md)

## 参考资料

[Linux 内核调试 七：qemu网络配置_lqonlylove的博客-CSDN博客](https://blog.csdn.net/OnlyLove_/article/details/124536607)

[qemu虚拟机配置网络_qemu 配置网络_千墨的博客-CSDN博客](https://blog.csdn.net/jcf147/article/details/131290211)

[cereal Docs - Main (uscilab.github.io)](https://uscilab.github.io/cereal/index.html)
