// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2023 Ruipeng Hong, SYSU */

#include "vmlinux.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "event_defs.h"
#include "hook_point.h"
#include "system_macro.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define BIO_TRACE_MASK (1 << BIO_TRACE_COMPLETION)

#define DEBUG 1
#ifdef DEBUG
#define bpf_debug(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define bpf_debug(fmt, ...)
#endif

struct request *cmd_to_rq(void *cmd)
{
	return (void *)cmd - (sizeof(struct request));
}

// HINT:
// 设置进程过滤是必须的！
// 这是出于现在大多数应用都是多线程的，如果不设置，会导致大量的无用的数据

// a map to store how many processes are referring to a inode
// if the inode is not in the map, it means no process is referring to it
// if the inode is in the map, it means there are some processes are referring
// to it
// assist to filter some event in block layer
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, long);
  __type(value, int);
  __uint(max_entries, 1 << 10);
} inode_ref_map SEC(".maps");

// a map to store how many processes are referring to a file
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, long);
  __uint(max_entries, 1 << 10);
} fd_ref_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, 1 << 10);
} fd_filted_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} ringbuffer SEC(".maps");


volatile struct filter_config filter_config = {
    .tgid = 0,
    .tid = 0,
    .inode = 0,
    .directory_inode = 0,
    .dev = 0,
    .command_len = 0,
    .filter_by_command = 0,
    .cgroup_id = 0,
};

volatile short qemu_enable;    // 必需加上至少进程级的过滤
volatile short syscall_enable; // 必需加上至少进程级的过滤
volatile short vfs_enable;     // 必需加上至少进程级的过滤
volatile short block_enable;
volatile short scsi_enable;
volatile short nvme_enable;
volatile short filemap_enable;
volatile short iomap_enable;
volatile short sched_enable;
volatile short virtio_enable;


long long dropped __attribute__((aligned(128))) = 0;

// return 1, means will be filtered
// return 0, means will be traced
// trace pid = 0 and target pid
// trace target device
static inline int task_comm_dropable(char *comm) {
  if (filter_config.filter_by_command == 0) {
    return 0;
  }
  for (int i = 0; i < MAX_COMM_LEN; i++) {
    if (comm[i] == '\0') {
      break;
    }
    if (comm[i] != filter_config.command[i]) {
      return 1;
    }
  }
  return 0;
}


static int inline pid_filter(pid_t tgid, pid_t tid) {
  // assert(filter_config.tgid != 0 || filter_config.tid != 0); !
  if (filter_config.tgid !=0 && filter_config.tgid != tgid) {
    return 1;
  }
  if (filter_config.tid != 0 && filter_config.tid != tid) {
    return 1;
  }
  return 0;
}

static int inline get_and_filter_pid(pid_t *tgid, pid_t *tid) {
  u64 id = bpf_get_current_pid_tgid();
  *tgid = id >> 32;
  *tid = id & 0xffffffff;
  return pid_filter(*tgid, *tid);
}

static int inline filter_inode_dev_dir(struct inode *iinode, struct file *file,
                                ino_t *inode, dev_t *devp, ino_t *dir_inodep) {
  if (filter_config.inode != 0) {
    ino_t ino = BPF_CORE_READ(iinode, i_ino);
    if(filter_config.inode != ino) {
      return 1;
    }
    *inode = ino;
  }
  if (filter_config.dev != 0) {
    dev_t dev = BPF_CORE_READ(iinode, i_sb, s_dev);
    if (filter_config.dev != dev) {
      return 1;
    }
    *devp = dev;
  }

  if (filter_config.directory_inode != 0) {
    struct path p = BPF_CORE_READ(file, f_path);
    ino_t dir_ino = BPF_CORE_READ(p.dentry, d_inode, i_ino);
    if (filter_config.directory_inode != dir_ino) {
      return 1;
    }
    *dir_inodep = dir_ino;
  }
  return 0;
}

// TODO:
// 如果遇到一些不属于追踪范围的请求，可能已经判断过不属于追踪范围，但是还是会被追踪
// 由于已经通过 pid 过滤了，所以这种情况出现的请求对应的文件描述符可能不会太多
// 所以通过一个 map 来记录一下，作为短路判断
// FIXME: 通过追踪文件描述符的开启和回收来维护这个 map
static int inline update_fd_inode_map_and_filter_dev_inode_dir(int fd, ino_t *inodep,
                                                        dev_t *devp,
                                                        ino_t *dir_inodep) {
  int ret = 0;
  ino_t inode = 0;
  dev_t dev = 0;
  ino_t dir_inode = 0;
  struct task_struct *task = bpf_get_current_task_btf();
  struct files_struct *files = task->files;
  struct fdtable *fdt;
  struct file **fdd;
  struct file *file;
  fdt = files->fdt;
  fdd = fdt->fd;
  bpf_core_read(&file, sizeof(struct file *), fdd + fd);
  struct inode *iinode = BPF_CORE_READ(file, f_inode);
  // filter and update filterd fd map
  ret = filter_inode_dev_dir(iinode, file, &inode, &dev, &dir_inode);

  if(ret){
    return 1;
  }
  if (inodep != NULL)
    *inodep = inode;
  if (devp != NULL)
    *devp = dev;
  if (dir_inodep != NULL)
    *dir_inodep = dir_inode;
  return 0;
}


// 如果存在用户态追踪的话，可以辅助过滤系统调用
// 目前对 QEMU 支持较好，因为 QEMU 对磁盘的维护只用到对指定文件偏移的读写
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, long long);
	__uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // 不同文件的 rb 会共享成一个
} tid_offset_map SEC(".maps"); 

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, 1024);
} tid_syscall_enter_map SEC(".maps");


/* read_write syscall  read_write.c */
// read_enter/exit
SEC("ksyscall/read")
int BPF_KPROBE_SYSCALL(trace_read, int fd, void *buf, size_t count) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  if(qemu_enable){ // qemu 维护虚拟磁盘时不会用这个系统调用
    bpf_debug("qemu untracked read enter\n");
    return 0;
  }

  ino_t inode = 0;
  ino_t dir_inode = 0;
  dev_t dev = 0;
  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, &inode, &dev, &dir_inode);
  if (ret) {
    return 0;
  }

  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if (!e) {
    return 0;
  }
  bpf_map_update_elem(&tid_syscall_enter_map, &tid, &tid, BPF_ANY);
  e->event_type = syscall__read;
  e->info_type = syscall_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.fd  = fd;
  e->syscall_layer_info.inode = inode;
  e->syscall_layer_info.dir_inode = dir_inode;
  e->syscall_layer_info.dev = dev;
  bpf_debug("syscall read enter: fd %d buf %lx count %lu\n", fd, buf, count);
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("kretsyscall/read")
int BPF_KRETPROBE(trace_read_ret, int ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  if(qemu_enable){ // qemu 维护虚拟磁盘时不会用这个系统调用
    bpf_debug("qemu untracked read exit\n");
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("read exit without enter\n");
    return 0;
  }
  bpf_map_delete_elem(&tid_syscall_enter_map, &tid);
  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = syscall__read;
  e->info_type = syscall_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.ret = ret;
  bpf_ringbuf_submit(e, 0);  
  bpf_debug("syscall read exit\n");
  return 0;
}


// wirte_enter/exit
SEC("ksyscall/write")
int BPF_KSYSCALL(write, int fd, void *buf, size_t count) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  if(qemu_enable){ // qemu 维护虚拟磁盘时不会用这个系统调用
    bpf_debug("qemu untracked write enter\n");
    return 0;
  }
  ino_t inode = 0;
  ino_t dir_inode = 0;
  dev_t dev = 0;
  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, &inode, &dev, &dir_inode);
  if (ret) {
    return 0;
  }
  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if (!e) {
    return 0;
  }
  bpf_map_update_elem(&tid_syscall_enter_map, &tid, &tid, BPF_ANY);
  e->event_type = syscall__write;
  e->info_type = syscall_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.fd  = fd;
  e->syscall_layer_info.inode = inode;
  e->syscall_layer_info.dir_inode = dir_inode;
  e->syscall_layer_info.dev = dev;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall write enter: fd %d buf %lx count %lu\n", fd, buf, count);
  return 0;
}
SEC("kretsyscall/write")
int BPF_KRETPROBE(write_ret,int ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  if(qemu_enable){ // qemu 维护虚拟磁盘时不会用这个系统调用
    bpf_debug("qemu untracked write exit\n");
    return 0;
  }
  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("write exit without enter\n");
    return 0;
  }
  bpf_map_delete_elem(&tid_syscall_enter_map, &tid);
  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = syscall__write;
  e->info_type = syscall_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.ret = ret;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall write exit\n");
  return 0;
}
// readv_enter/exit
SEC("ksyscall/readv")
int BPF_KPROBE_SYSCALL(readv, int fd, struct iovec *vec, unsigned long vlen) {
  if (!syscall_enable) {
    return 0;
  }
  if(qemu_enable){
    bpf_debug("qemu untracked readv enter\n");
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t inode = 0;
  ino_t dir_inode = 0;
  dev_t dev = 0;

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, &inode, &dev, &dir_inode);
  if (ret) {
    return 0;
  }
  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if (!e) {
    return 0;
  }
  bpf_map_update_elem(&tid_syscall_enter_map, &tid, &tid, BPF_ANY);
  e->event_type = syscall__readv;
  e->info_type = syscall_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.fd  = fd;
  e->syscall_layer_info.inode = inode;
  e->syscall_layer_info.dir_inode = dir_inode;
  e->syscall_layer_info.dev = dev;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall readv enter: fd %d vec %lx vlen %lu\n", fd, vec, vlen);
  return 0;
}
SEC("kretsyscall/readv")
int BPF_KRETPROBE(readv_ret,int ret) {
  if (!syscall_enable) {
    return 0;
  }
  if(qemu_enable){
    bpf_debug("qemu untracked readv exit\n");
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("readv exit without enter\n");
    return 0;
  }
  bpf_map_delete_elem(&tid_syscall_enter_map, &tid);
  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = syscall__readv;
  e->info_type = syscall_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.ret = ret;
  bpf_ringbuf_submit(e, 0);

  bpf_debug("syscall readv exit\n");
  return 0;
}

// writev_enter/exit
SEC("ksyscall/writev")
int BPF_KPROBE_SYSCALL(writev, int fd, struct iovec *vec, unsigned long vlen) {
  if (!syscall_enable) {
    return 0;
  }
  if(qemu_enable){
    bpf_debug("qemu untracked writev enter\n");
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  ino_t inode = 0;
  ino_t dir_inode = 0;
  dev_t dev = 0;

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, &inode, &dev, &dir_inode);
  if (ret) {
    return 0;
  }
  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if (!e) {
    return 0;
  }
  bpf_map_update_elem(&tid_syscall_enter_map, &tid, &tid, BPF_ANY);
  e->event_type = syscall__writev;
  e->info_type = syscall_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.fd  = fd;
  e->syscall_layer_info.inode = inode;
  e->syscall_layer_info.dir_inode = dir_inode;
  e->syscall_layer_info.dev = dev;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall writev enter: fd %d vec %lx vlen %lu\n", fd, vec, vlen);
  return 0;
}
SEC("kretsyscall/writev")
int BPF_KRETPROBE(writev_ret,int ret) {
  if (!syscall_enable) {
    return 0;
  }
  if(qemu_enable){
    bpf_debug("qemu untracked writev exit\n");
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("writev exit without enter\n");
    return 0;
  }
  bpf_map_delete_elem(&tid_syscall_enter_map, &tid);
  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = syscall__writev;
  e->info_type = syscall_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.ret = ret;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall writev exit\n");
  return 0;
}
// pread64_enter/exit
SEC("ksyscall/pread64")
int BPF_KPROBE_SYSCALL(pread64, int fd, void *buf, size_t count,
                       loff_t offset) {
  if (!syscall_enable) {
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  if(qemu_enable){ // check offset
    long long *offset_ref = bpf_map_lookup_elem(&tid_offset_map, &tid);
    if(offset_ref == NULL || offset != *offset_ref){
      bpf_debug("qemu untracked pread64 enter %lx\n", offset);
      return 0;
    }
  }

  ino_t inode = 0;
  ino_t dir_inode = 0;
  dev_t dev = 0;
  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, &inode, &dev, &dir_inode);
  if (ret) {
    return 0;
  }
  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if (!e) {
    return 0;
  }
  bpf_map_update_elem(&tid_syscall_enter_map, &tid, &tid, BPF_ANY);
  e->event_type = syscall__pread64;
  e->info_type = syscall_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.fd  = fd;
  e->syscall_layer_info.inode = inode;
  e->syscall_layer_info.dir_inode = dir_inode;
  e->syscall_layer_info.dev = dev;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall pread64 enter: fd %d count %lu offset %lu\n", fd, count, offset);
  return 0;
}
SEC("kretsyscall/pread64")
int BPF_KRETPROBE(pread64_ret, int ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("pread64 exit without enter\n");
    return 0;
  }
  bpf_map_delete_elem(&tid_syscall_enter_map, &tid);
  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = syscall__pread64;
  e->info_type = syscall_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.ret = ret;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall pread64 exit\n");
  return 0;
}
// pwrite64_enter/exit
SEC("ksyscall/pwrite64")
int BPF_KPROBE_SYSCALL(pwrite64, int fd, void *buf, size_t count,
                       loff_t offset) {
  if (!syscall_enable) {
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  if(qemu_enable){
    long long *offset_ref = bpf_map_lookup_elem(&tid_offset_map, &tid);
    if(offset_ref == NULL || offset != *offset_ref){
      bpf_debug("qemu untracked pwrite64 enter %lx\n", offset);
      return 0;
    }
  }

  ino_t inode = 0;
  ino_t dir_inode = 0;
  dev_t dev = 0;

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, &inode, &dev, &dir_inode);
  if (ret) {
    return 0;
  }

  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if (!e) {
    return 0;
  }
  bpf_map_update_elem(&tid_syscall_enter_map, &tid, &tid, BPF_ANY);
  e->event_type = syscall__pwrite64;
  e->info_type = syscall_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.fd  = fd;
  e->syscall_layer_info.inode = inode;
  e->syscall_layer_info.dir_inode = dir_inode;
  e->syscall_layer_info.dev = dev;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall pwrite64 enter: fd %d count %lu offset %lu\n", fd, count, offset);
  return 0;
}
SEC("kretsyscall/pwrite64")
int BPF_KRETPROBE(pwrite64_ret, int ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("pwrite64 exit without enter\n");
    return 0;
  }
  bpf_map_delete_elem(&tid_syscall_enter_map, &tid);
  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = syscall__pwrite64;
  e->info_type = syscall_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.ret = ret;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall pwrite64 exit\n");
  return 0;
}
// preadv_enter/exit
SEC("ksyscall/preadv")
int BPF_KPROBE_SYSCALL(preadv, int fd, struct iovec *vec, unsigned long vlen, long long offset) {
  if (!syscall_enable) {
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  if(qemu_enable){
    long long *offset_ref = bpf_map_lookup_elem(&tid_offset_map, &tid);
    if(offset_ref == NULL || offset != *offset_ref){
      bpf_debug("qemu untracked preadv enter %lx\n", offset);
      return 0;
    }
  }
  ino_t inode = 0;
  ino_t dir_inode = 0;
  dev_t dev = 0;

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, &inode, &dev, &dir_inode);
  if (ret) {
    return 0;
  }

  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if (!e) {
    return 0;
  }
  bpf_map_update_elem(&tid_syscall_enter_map, &tid, &tid, BPF_ANY);
  e->event_type = syscall__preadv;
  e->info_type = syscall_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.fd  = fd;
  e->syscall_layer_info.inode = inode;
  e->syscall_layer_info.dir_inode = dir_inode;
  e->syscall_layer_info.dev = dev;
  bpf_ringbuf_submit(e, 0);

  bpf_debug("syscall preadv enter: fd %d vec %lx vlen %lu\n", fd, vec, vlen);
  return 0;
}
SEC("kretsyscall/preadv")
int BPF_KRETPROBE(preadv_ret, int ret){
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("preadv exit without enter\n");
    return 0;
  }
  bpf_map_delete_elem(&tid_syscall_enter_map, &tid);
  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = syscall__preadv;
  e->info_type = syscall_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.ret = ret;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall preadv exit\n");
  return 0;
}
// pwritev_enter/exit
SEC("ksyscall/pwritev")
int BPF_KPROBE_SYSCALL(pwritev, int fd, struct iovec *vec, unsigned long vlen,
                       loff_t offset) {
  if (!syscall_enable) {
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  if(qemu_enable){
    long long *offset_ref = bpf_map_lookup_elem(&tid_offset_map, &tid);
    if(offset_ref == NULL || offset != *offset_ref){
      bpf_debug("qemu untracked pwritev enter %lx\n", offset);
      return 0;
    }
  }

  ino_t inode = 0;
  ino_t dir_inode = 0;
  dev_t dev = 0;

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, &inode, &dev, &dir_inode);
  if (ret) {
    return 0;
  }

  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if (!e) {
    return 0;
  }
  bpf_map_update_elem(&tid_syscall_enter_map, &tid, &tid, BPF_ANY);
  e->event_type = syscall__pwritev;
  e->info_type = syscall_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.fd  = fd;
  e->syscall_layer_info.inode = inode;
  e->syscall_layer_info.dir_inode = dir_inode;
  e->syscall_layer_info.dev = dev;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall pwritev enter: fd %d vec %lx vlen %lu\n", fd, vec, vlen);
  return 0;
}
SEC("kretsyscall/pwritev")
int BPF_KRETPROBE(pwritev_ret,int ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("pwritev exit without enter\n");
    return 0;
  }
  bpf_map_delete_elem(&tid_syscall_enter_map, &tid);
  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = syscall__pwritev;
  e->info_type = syscall_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.ret = ret;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall pwritev exit\n");
  return 0;
}

/* fs/sync.c*/
// sync
// fsync
SEC("ksyscall/fsync")
int BPF_KPROBE_SYSCALL(fsync, int fd) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  if(qemu_enable){
    long long *offset_ref = bpf_map_lookup_elem(&tid_offset_map, &tid);
    if(offset_ref == NULL || *offset_ref != -RQ_TYPE_FLUSH ){
      bpf_debug("qemu untracked fsync enter\n");
      return 0;
    }
  }

  ino_t inode = 0;
  ino_t dir_inode = 0;
  dev_t dev = 0;

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, &inode, &dev, &dir_inode);
  if (ret) {
    return 0;
  }

  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if (!e) {
    return 0;
  }
  bpf_map_update_elem(&tid_syscall_enter_map, &tid, &tid, BPF_ANY);
  e->event_type = syscall__fsync;
  e->info_type = syscall_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.fd  = fd;
  e->syscall_layer_info.inode = inode;
  e->syscall_layer_info.dir_inode = dir_inode;
  e->syscall_layer_info.dev = dev;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall fsync enter: fd %d\n", fd);
  return 0;
}
SEC("kretsyscall/fsync")
int BPF_KRETPROBE(fsync_ret,int ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("fsync exit without enter\n");
    return 0;
  }
  bpf_map_delete_elem(&tid_syscall_enter_map, &tid);
  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = syscall__fsync;
  e->info_type = syscall_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.ret = ret;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall fsync exit\n");
  return 0;
}

// fdatasync
SEC("ksyscall/fdatasync")
int BPF_KPROBE_SYSCALL(fdatasync, int fd) {
  if (!syscall_enable) {
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  if(qemu_enable){
    long long *offset_ref = bpf_map_lookup_elem(&tid_offset_map, &tid);
    if(offset_ref == NULL || *offset_ref != -RQ_TYPE_FLUSH ){
      bpf_debug("qemu untracked fsync enter\n");
      return 0;
    }
  }

  ino_t inode = 0;
  ino_t dir_inode = 0;
  dev_t dev = 0;

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, &inode, &dev, &dir_inode);
  if (ret) {
    return 0;
  }

  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if (!e) {
    return 0;
  }
  bpf_map_update_elem(&tid_syscall_enter_map, &tid, &tid, BPF_ANY);
  e->event_type = syscall__fdatasync;
  e->info_type = syscall_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.fd  = fd;
  e->syscall_layer_info.inode = inode;
  e->syscall_layer_info.dir_inode = dir_inode;
  e->syscall_layer_info.dev = dev;
  bpf_ringbuf_submit(e, 0);

  bpf_debug("syscall fdatasync enter: fd %d\n", fd);
  return 0;
}
SEC("kretsyscall/fdatasync")
int BPF_KRETPROBE(fdatasync_ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("fdatasync exit without enter\n");
    return 0;
  }
  bpf_map_delete_elem(&tid_syscall_enter_map, &tid);
  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = syscall__fdatasync;
  e->info_type = syscall_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall fdatasync exit\n");
  return 0;
}

// sync_file_range
SEC("ksyscall/sync_file_range")
int BPF_KPROBE_SYSCALL(sync_file_range, int fd, loff_t offset, loff_t nbytes,
                       unsigned int flags) {
  if (!syscall_enable) {
    return 0;
  }

  if(qemu_enable){
    bpf_debug("qemu untracked sync_file_range enter\n");
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t inode = 0;
  ino_t dir_inode = 0;
  dev_t dev = 0;

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, NULL, NULL, NULL);
  if (ret) {
    return 0;
  }

  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if (!e) {
    return 0;
  }
  bpf_map_update_elem(&tid_syscall_enter_map, &tid, &tid, BPF_ANY);
  e->event_type = syscall__sync_file_range;
  e->info_type = syscall_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  e->syscall_layer_info.fd  = fd;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall sync_file_range enter: fd %d offset %lu nbytes %lu \n", fd,
             offset, nbytes);
  return 0;
}
SEC("kretsyscall/sync_file_range")
int BPF_KRETPROBE(sync_file_range_ret) {
  if (!syscall_enable) {
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("sync_file_range exit without enter\n");
    return 0;
  }
  bpf_map_delete_elem(&tid_syscall_enter_map, &tid);
  struct event * e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = syscall__sync_file_range;
  e->info_type = syscall_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->syscall_layer_info.tgid = tgid;
  e->syscall_layer_info.tid = tid;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("syscall sync_file_range exit\n");
  return 0;
}

/* vfs layer */
static int inline vfs_filter_inode(ino_t inode) {
  if (filter_config.inode != 0 && filter_config.inode != inode) {
    return 1;
  }
  // check inode_ref_map
  int *inode_ref = bpf_map_lookup_elem(&inode_ref_map, &inode);
  if (inode_ref == NULL) {
    return 1;
  }

  return 0;
}

struct rw_area {
  ino_t inode;
  loff_t offset;
  loff_t len;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, struct rw_area);
  __uint(max_entries, 1024);
} tid_rw_area_map SEC(".maps");

// 对于 vfs 层的挂载点，由于是完全同步的，所以直接查询当前进程是否处于某个 syscall 下
// 不需要通过 inode 过滤
// 对于后续 block layer 层需要用到 inode 号的对应
// 可以由用户态读 fd 和 inode map 来获取关联
// // do_iter_read
SEC("fentry/do_iter_read")
int BPF_PROG(trace_do_iter_read, struct file *file, struct iov_iter *iter) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("do_iter_read enter without enter\n");
    return 0;
  } 
  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  unsigned long nr_bytes = iter->count;
  loff_t *pos = NULL;
  loff_t offset = 0;
  bpf_core_read(&pos, sizeof(pos), ctx + 2);
  bpf_core_read(&offset, sizeof(offset), pos);

  struct rw_area area = {
      .inode = file->f_inode->i_ino,
      .offset = offset,
      .len = nr_bytes,
  };
  bpf_map_update_elem(&tid_rw_area_map, &tid, &area, BPF_ANY);
  e->event_type = fs__do_iter_read;
  e->info_type = fs_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  e->fs_layer_info.offset = offset;
  e->fs_layer_info.bytes = nr_bytes;
  bpf_ringbuf_submit(e, 0);
  bpf_printk("do_iter_read enter:	offset %lu len %lu\n",  offset, nr_bytes);
  return 0;
}
SEC("fexit/do_iter_read")
int BPF_PROG(trace_do_iter_read_exit, struct file *file) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("do_iter_read exit without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = fs__do_iter_read;
  e->info_type = fs_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  bpf_ringbuf_submit(e, 0);
  return 0;
}
// do_iter_write
SEC("fentry/do_iter_write")
int BPF_PROG(trace_do_iter_write, struct file *file, struct iov_iter *iter) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("do_iter_write enter without enter\n");
    return 0;
  }
  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  unsigned long nr_bytes = iter->count;
  loff_t *pos = NULL;
  loff_t offset = 0;
  bpf_core_read(&pos, sizeof(pos), ctx + 2);
  bpf_core_read(&offset, sizeof(offset), pos);

  struct rw_area area = {
      .inode = file->f_inode->i_ino,
      .offset = offset,
      .len = nr_bytes,
  };

  bpf_map_update_elem(&tid_rw_area_map, &tid, &area, BPF_ANY);
  e->event_type = fs__do_iter_write;
  e->info_type = fs_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  e->fs_layer_info.offset = offset;
  e->fs_layer_info.bytes = nr_bytes;
  bpf_ringbuf_submit(e, 0);
  return 0;
}
SEC("fexit/do_iter_write")
int BPF_PROG(trace_do_iter_write_exit, struct file *file) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("do_iter_write exit without enter\n");
    return 0;
  }
  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = fs__do_iter_write;
  e->info_type = fs_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  bpf_ringbuf_submit(e, 0);
  bpf_printk("do_iter_write exit:	\n");
  return 0;
}
// vfs_iocb_iter_write
SEC("fentry/vfs_iocb_iter_write")
int BPF_PROG(trace_vfs_iocb_iter_write, struct file *file, struct kiocb *iocb,
             struct iov_iter *iter) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("vfs_iocb_iter_write enter without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  unsigned long nr_bytes = iter->count;
  loff_t offset = iocb->ki_pos;

  struct rw_area area = {
      .inode = file->f_inode->i_ino,
      .offset = offset,
      .len = nr_bytes,
  };
  bpf_map_update_elem(&tid_rw_area_map, &tid, &area, BPF_ANY);

  e->event_type = fs__vfs_iocb_iter_write;
  e->info_type = fs_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  e->fs_layer_info.offset = offset;
  e->fs_layer_info.bytes = nr_bytes;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("vfs_iocb_iter_write enter:	offset %lld, bytes %lu\n", offset,
            nr_bytes);
  return 0;
}
SEC("fexit/vfs_iocb_iter_write")
int BPF_PROG(trace_vfs_iocb_iter_write_exit, struct file *file,
             struct kiocb *iocb, struct iov_iter *iter, ssize_t ret) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("vfs_iocb_iter_write exit without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  e->event_type = fs__vfs_iocb_iter_write;
  e->info_type = fs_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("vfs_iocb_iter_write exit:	ret %ld\n", ret);
  return 0;
}
// vfs_iocb_iter_read
SEC("fentry/vfs_iocb_iter_read")
int BPF_PROG(trace_vfs_iocb_iter_read, struct file *file, struct kiocb *iocb,
             struct iov_iter *iter) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("vfs_iocb_iter_read enter without enter\n");
    return 0;
  }
  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  unsigned long nr_bytes = iter->count;
  loff_t offset = iocb->ki_pos;
  struct rw_area area = {
      .inode = file->f_inode->i_ino,
      .offset = offset,
      .len = nr_bytes,
  };
  bpf_map_update_elem(&tid_rw_area_map, &tid, &area, BPF_ANY);

  e->event_type = fs__vfs_iocb_iter_read;
  e->info_type = fs_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  e->fs_layer_info.offset = offset;
  e->fs_layer_info.bytes = nr_bytes;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("vfs_iocb_iter_read enter:	offset %lld, bytes %lu\n", offset,
            nr_bytes);
  return 0;
}
SEC("fexit/vfs_iocb_iter_read")
int BPF_PROG(trace_vfs_iocb_iter_read_exit, struct file *file,
             struct kiocb *iocb, struct iov_iter *iter, ssize_t ret) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("vfs_iocb_iter_read exit without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  e->event_type = fs__vfs_iocb_iter_read;
  e->info_type = fs_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("vfs_iocb_iter_read exit:	ret %ld\n", ret);
  return 0;
}
// vfs_read
SEC("fentry/vfs_read")
int BPF_PROG(trace_vfs_read, struct file *file, char *buf, size_t count) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("vfs_read enter without enter\n");
    return 0;
  }

  unsigned long nr_bytes = count;
  loff_t *pos = NULL;
  loff_t offset = 0;
  bpf_core_read(&pos, sizeof(pos), ctx + 2);
  bpf_core_read(&offset, sizeof(offset), pos);

  struct rw_area area = {
      .inode = file->f_inode->i_ino,
      .offset = offset,
      .len = nr_bytes,
  };
  bpf_map_update_elem(&tid_rw_area_map, &tid, &area, BPF_ANY);
  
  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  e->event_type = fs__vfs_read;
  e->info_type = fs_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  e->fs_layer_info.offset = offset;
  e->fs_layer_info.bytes = nr_bytes;
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("fexit/vfs_read")
int BPF_PROG(trace_vfs_read_exit, struct file *file, char *buf, size_t count) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("vfs_read exit without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  e->event_type = fs__vfs_read;
  e->info_type = fs_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  bpf_ringbuf_submit(e, 0);

  return 0;
}
// vfs_write
SEC("fentry/vfs_write")
int BPF_PROG(trace_vfs_write, struct file *file, char *buf, size_t count) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("vfs_write enter without enter\n");
    return 0;
  }


  unsigned long nr_bytes = count;
  loff_t *pos = NULL;
  loff_t offset = 0;
  bpf_core_read(&pos, sizeof(pos), ctx + 2);
  bpf_core_read(&offset, sizeof(offset), pos);
  
  struct rw_area area = {
      .inode = file->f_inode->i_ino,
      .offset = offset,
      .len = nr_bytes,
  };
  bpf_map_update_elem(&tid_rw_area_map, &tid, &area, BPF_ANY);
  
  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  e->event_type = fs__vfs_write;
  e->info_type = fs_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  e->fs_layer_info.offset = offset;
  e->fs_layer_info.bytes = nr_bytes;
  bpf_ringbuf_submit(e, 0);

  return 0;
}
SEC("fexit/vfs_write")
int BPF_PROG(trace_vfs_write_exit, struct file *file, char *buf, size_t count) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("vfs_write exit without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  e->event_type = fs__vfs_write;
  e->info_type = fs_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("fentry/vfs_fsync_range")
int BPF_PROG(trace_vfs_fsync_range, struct file *file, loff_t start, loff_t end,
             int datasync) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("vfs_fsync_range enter without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  struct rw_area area = {
      .inode = file->f_inode->i_ino,
      .offset = start,
      .len = end - start,
  };
  bpf_map_update_elem(&tid_rw_area_map, &tid, &area, BPF_ANY);

  e->event_type = fs__vfs_fsync_range;
  e->info_type = fs_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  e->fs_layer_info.offset = start;
  e->fs_layer_info.bytes = end - start;
  bpf_ringbuf_submit(e, 0);

  return 0;
}

// generic_file_read_iter
SEC("fentry/generic_file_read_iter")
int BPF_PROG(trace_generic_file_read_iter, struct kiocb *iocb,
             struct iov_iter *iter) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("generic_file_read_iter enter without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  struct file *file = iocb->ki_filp;
  loff_t offset = iocb->ki_pos;
  unsigned long nr_bytes = iter->count;

  struct rw_area area = {
      .inode = file->f_inode->i_ino,
      .offset = offset,
      .len = nr_bytes,
  };

  bpf_map_update_elem(&tid_rw_area_map, &tid, &area, BPF_ANY);

  e->event_type = fs__generic_file_read_iter;
  e->info_type = fs_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  e->fs_layer_info.offset = offset;
  e->fs_layer_info.bytes = nr_bytes;
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("fexit/generic_file_read_iter")
int BPF_PROG(trace_generic_file_read_iter_exit, struct kiocb *iocb,
             struct iov_iter *iter, ssize_t ret) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("generic_file_read_iter exit without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  e->event_type = fs__generic_file_read_iter;
  e->info_type = fs_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  bpf_ringbuf_submit(e, 0);

  return 0;
}
// generic_file_write_iter
SEC("fentry/generic_file_write_iter")
int BPF_PROG(trace_generic_file_write_iter, struct kiocb *iocb,
             struct iov_iter *iter) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("generic_file_write_iter enter without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  struct file *file = iocb->ki_filp;
  loff_t offset = iocb->ki_pos;
  unsigned long nr_bytes = iter->count;

  struct rw_area area = {
      .inode = file->f_inode->i_ino,
      .offset = offset,
      .len = nr_bytes,
  };

  bpf_map_update_elem(&tid_rw_area_map, &tid, &area, BPF_ANY);

  e->event_type = fs__generic_file_write_iter;
  e->info_type = fs_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  e->fs_layer_info.offset = offset;
  e->fs_layer_info.bytes = nr_bytes;
  bpf_ringbuf_submit(e, 0);
  return 0;
}
SEC("fexit/generic_file_write_iter")
int BPF_PROG(trace_generic_file_write_iter_exit, struct kiocb *iocb,
             struct iov_iter *iter, ssize_t ret) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("generic_file_write_iter exit without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  e->event_type = fs__generic_file_write_iter;
  e->info_type = fs_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  bpf_ringbuf_submit(e, 0);
  return 0;
}

// filemap_get_pages
SEC("fentry/filemap_get_pages")
int BPF_PROG(trace_filemap_get_pages, struct kiocb *iocb,
             struct iov_iter *iter) {
  if (!vfs_enable) {
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    bpf_debug("filemap_get_pages enter without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  struct file *file = iocb->ki_filp;
  loff_t offset = iocb->ki_pos;
  unsigned long nr_bytes = iter->count;

  struct rw_area area = {
      .inode = file->f_inode->i_ino,
      .offset = offset,
      .len = nr_bytes,
  };

  bpf_map_update_elem(&tid_rw_area_map, &tid, &area, BPF_ANY);

  e->event_type = fs__filemap_get_pages;
  e->info_type = fs_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  e->fs_layer_info.offset = offset;
  e->fs_layer_info.bytes = nr_bytes;
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("fexit/filemap_get_pages")
int BPF_PROG(trace_filemap_get_pages_exit, struct kiocb *iocb,
             struct iov_iter *iter, ssize_t ret) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("filemap_get_pages exit without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  e->event_type = fs__filemap_get_pages;
  e->info_type = fs_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  bpf_ringbuf_submit(e, 0);
  return 0;
}

// file_write_and_wait_range
SEC("fentry/file_write_and_wait_range")
int BPF_PROG(trace_file_write_and_wait_range, struct file *file, loff_t start,
             loff_t end) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("file_write_and_wait_range enter without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  struct rw_area area = {
      .inode = file->f_inode->i_ino,
      .offset = start,
      .len = end - start,
  };

  bpf_map_update_elem(&tid_rw_area_map, &tid, &area, BPF_ANY);

  e->event_type = fs__file_write_and_wait_range;
  e->info_type = fs_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  e->fs_layer_info.offset = start;
  e->fs_layer_info.bytes = end - start;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("file_write_and_wait_range enter\n");
  return 0;
}

SEC("fexit/file_write_and_wait_range")
int BPF_PROG(trace_file_write_and_wait_range_exit, struct file *file,
             loff_t start, loff_t end) {
  if (!vfs_enable) {
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("file_write_and_wait_range exit without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  e->event_type = fs__file_write_and_wait_range;
  e->info_type = fs_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  bpf_ringbuf_submit(e, 0);
  bpf_printk("file_write_and_wait_range exit\n");
  return 0;
}

/* iomap */
// iomap_dio_rw
SEC("fentry/iomap_dio_rw")
int BPF_PROG(trace_enter_iomap_dio_rw, struct kiocb *iocb,
             struct iov_iter *iter) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("iomap_dio_rw enter without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  struct file *file = iocb->ki_filp;
  loff_t offset = iocb->ki_pos;
  unsigned long nr_bytes = iter->count;

  struct rw_area area = {
      .inode = file->f_inode->i_ino,
      .offset = offset,
      .len = nr_bytes,
  };

  bpf_map_update_elem(&tid_rw_area_map, &tid, &area, BPF_ANY);

  e->event_type = iomap__dio_rw;
  e->info_type = fs_layer;
  e->trigger_type = ENTRY;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  e->fs_layer_info.offset = offset;
  e->fs_layer_info.bytes = nr_bytes;
  bpf_ringbuf_submit(e, 0);
  bpf_debug("iomap_dio_rw enter\n");
  return 0;
}
SEC("fexit/iomap_dio_rw")
int BPF_PROG(trace_exit_iomap_dio_rw, struct kiocb *iocb, struct iov_iter *iter,
             ssize_t ret) {
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int* tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_syscall_enter == NULL){
    // bpf_debug("iomap_dio_rw exit without enter\n");
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  struct file *file = iocb->ki_filp;
  loff_t offset = iocb->ki_pos;
  unsigned long nr_bytes = iter->count;
  
  struct rw_area area = {
      .inode = file->f_inode->i_ino,
      .offset = offset,
      .len = nr_bytes,
  };

  bpf_map_update_elem(&tid_rw_area_map, &tid, &area, BPF_ANY);

  e->event_type = iomap__dio_rw;
  e->info_type = fs_layer;
  e->trigger_type = EXIT;
  e->timestamp = bpf_ktime_get_ns();
  e->fs_layer_info.tgid = tgid;
  e->fs_layer_info.tid = tid;
  e->fs_layer_info.offset = offset;
  e->fs_layer_info.bytes = nr_bytes;
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("tp_btf/sched_switch")
int handle_tp_sched_1(struct bpf_raw_tracepoint_args *ctx) {
  if (!sched_enable) {
    return 0;
  }
  struct task_struct *prev = (struct task_struct *)(ctx->args[1]);
  struct task_struct *next = (struct task_struct *)(ctx->args[2]);
  pid_t prev_tid = BPF_CORE_READ(prev, pid);
  pid_t next_tid = BPF_CORE_READ(next, pid);

  if (prev_tid == next_tid) {
    return 0;
  }
  
  int* prev_tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &prev_tid);
  if(prev_tid_syscall_enter != NULL){
    struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
    if(e == NULL){
      return 0;
    }
    e->event_type = sched__switch;
    e->info_type = sched_layer;
    e->trigger_type = NOT_PAIR;
    e->timestamp = bpf_ktime_get_ns();
    e->sched_layer_info.prev_tid = prev_tid;
    e->sched_layer_info.next_tid = next_tid;
    bpf_ringbuf_submit(e, 0);
  }

  int* next_tid_syscall_enter = bpf_map_lookup_elem(&tid_syscall_enter_map, &next_tid);
  if(next_tid_syscall_enter != NULL){
    struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
    if(e == NULL){
      return 0;
    }
    e->event_type = sched__switch;
    e->info_type = sched_layer;
    e->trigger_type = NOT_PAIR;
    e->timestamp = bpf_ktime_get_ns();
    e->sched_layer_info.prev_tid = prev_tid;
    e->sched_layer_info.next_tid = next_tid;
    bpf_ringbuf_submit(e, 0);
  }
  return 0;
}

// a map to keep track of existing pages related to the inodes tracked
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, void*);
  __type(value, int);
  __uint(max_entries, 1<<10);
} page_ref_map SEC(".maps");

long long page_ref_map_cnt = 0;
long long page_dirty_cnt = 0;

// TODO: 分析 dirty/hit 的情况
//  进程级的 page cache 追踪
//  设备级的 page cache 追踪

/* page cache */ // 有可能其它进程把这个 page 给删除了，所以这里需要记录
SEC("tp_btf/mm_filemap_delete_from_page_cache") // 但是对 page 的记录，必须要全局记录
int handle_tp_filemap_1(struct bpf_raw_tracepoint_args *ctx) {
  if (!filemap_enable) {
    return 0;
  }

  struct page *page = (struct page *)(ctx->args[0]);
  // check page_ref_map
  // if exsits, then delete
  int *ref = bpf_map_lookup_elem(&page_ref_map, &page);
  if (ref == NULL) {
    return 0;
  } else {
    bpf_map_delete_elem(&page_ref_map, &page);
  }
  bpf_debug("delete page %lx page_ref_map: %d\n",page, *ref);
  return 0;
}

SEC("tp_btf/mm_filemap_add_to_page_cache")
int handle_tp_filemap_2(struct bpf_raw_tracepoint_args *ctx) {
  if (!filemap_enable) {
    return 0;
  }

  struct page *page = (struct page *)(ctx->args[0]);
  struct address_space *mapping = page->mapping;
  struct inode *inode = mapping->host;
  ino_t ino = inode->i_ino;
  // add to page_ref_map
  int *ref = bpf_map_lookup_elem(&page_ref_map, &page);
  if (ref == NULL) {
    int a = 0;
    bpf_map_update_elem(&page_ref_map, &page, &a, BPF_ANY);
  } else {
    bpf_debug("add page %lx page_ref_map: %d\n", page,*ref);
  }
  return 0;
}

SEC("fentry/mark_page_accessed")  // 只记录当前追踪的线程对 page 的访问情况
int BPF_PROG(trace_mark_page_accessed, struct page *page) {
  if (!filemap_enable) {
    return 0;
  }
  pid_t tgid, tid; 
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  // check page_ref_map
  // if exsits, then increase ref cnt
  int *ref = bpf_map_lookup_elem(&page_ref_map, &page);
  if (ref == NULL) {
    return 0;
  } else {
    (*ref)++;
    bpf_debug("mark_page_accessed page_ref_map: %d\n", *ref);
  }
  return 0;
}

SEC("tp_btf/writeback_dirty_page") // 只记录当前追踪的线程对 page 的写 dirty 情况（不算系统工作线程写回的）
int handle_tp_filemap_3(struct bpf_raw_tracepoint_args *ctx) {
  if (!filemap_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  struct page *page = (struct page *)(ctx->args[0]);
  // check page_ref_map
  // if exsits, record the ref cnt
  int *ref = bpf_map_lookup_elem(&page_ref_map, &page);
  if (ref == NULL) {
    return 0;
  } else {
    __sync_fetch_and_add(&page_ref_map_cnt, *ref);
    __sync_fetch_and_add(&page_dirty_cnt, 1);
    bpf_debug("writeback_dirty_page page_ref_map: %d\n", *ref);
  }
  return 0;
}


static inline bool rq_is_passthrough(unsigned int rq_cmd_flags) {
  if (rq_cmd_flags & REQ_OP_MASK) {
    unsigned int op = rq_cmd_flags & REQ_OP_MASK;
    if (op == REQ_OP_DRV_IN || op == REQ_OP_DRV_OUT) {
      return true;
    }
  }
  return false;
}


/* block layer (bio request) */
// bio refference map
// if the bio is not in the map, it means no process is referring to it
// if the bio is in the map, it means there are some processes are referring
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, void *);
  __type(value, int);
  __uint(max_entries, 1<<10);
} bio_ref_map SEC(".maps");

// request refference map
// if the request is not in the map, it means no process is referring to it
// if the request is in the map, it means there are some processes are referring
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, void *);
  __type(value, int);
  __uint(max_entries, 1<<10);
} request_ref_map SEC(".maps");
//TODO: 进程级别的 io 活动分析

long long global_bio_id = 0;
long long global_rq_id = 0;

// SEC("tp_btf/block_split") // 不影响主 bio，应该不用管
// int handle_tp3(struct bpf_raw_tracepoint_args *ctx)
// {
// 	struct bio *bio = (struct bio *)(ctx->args[0]);
// 	sector_t sector = bio->bi_iter.bi_sector;
// 	sector_t new_sector = (sector_t)(ctx->args[1]);
// 	bpf_printk("block_split target bio: %lx sector: %ld new_sector: %ld\n", bio, sector,
// 		   new_sector);
// 	return 0;
// }
int checkIntersection(loff_t start1, loff_t end1, loff_t start2, loff_t end2) {
  // [100,200] is not intersect with [200,300]
  if (start1 >= end2 || start2 >= end1) {
    return 0;
  }
  return 1;
}

SEC("tp_btf/block_bio_queue") // 开始追踪一个 bio
int handle_tp7(struct bpf_raw_tracepoint_args *ctx)
{
  if(!block_enable){
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    if(tid == 0){
      bpf_debug("filted tid = 0 bio queue\n");
      //TODO: trace whole system bio
    }
    return 0;
  }

  int* tid_in_syscall = bpf_map_lookup_elem(&tid_syscall_enter_map, &tid);
  if(tid_in_syscall == NULL){
    return 0;
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

	struct bio *bio = (struct bio *)(ctx->args[0]);
	struct bio_vec *first_bv = bio->bi_io_vec;
	struct page *first_page = first_bv->bv_page;

  // add to bio_ref_map
  long long bio_id = 0;
  int *bio_ref = bpf_map_lookup_elem(&bio_ref_map, &bio);
  if (bio_ref == NULL) {
    bio_id = __sync_fetch_and_add(&global_bio_id, 1);
    bpf_map_update_elem(&bio_ref_map, &bio, &bio_id, BPF_ANY);
    bpf_debug("block_bio_queue bio curr active_bio_cnt: %lld\n", bio_id);
  } else {
    bio_id = *bio_ref;
    bpf_debug("block_bio_queue bio %lx already in bio_ref_map\n", bio);
  }

   // 近似的计算 bio 对应文件逻辑地址的大致范围（认为 bio 的 bi_vec 是顺序递增的）
  // 用于和 vfs 的请求进行匹配
	int last_index = (bio->bi_vcnt - 1) & ((1<<20) - 1);

	struct bio_vec last_bv;
	bpf_core_read(&last_bv, sizeof(struct bio_vec), first_bv + last_index);
	int last_page_index = BPF_CORE_READ(last_bv.bv_page, index);
	loff_t start_offset = (first_page->index << 12) + first_bv->bv_offset;
	loff_t end_offset = (last_page_index << 12) + last_bv.bv_offset + last_bv.bv_len;
  e->event_type = block__bio_queue;
  e->info_type = block_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->block_layer_info.tgid = tgid;
  e->block_layer_info.tid = tid;
  e->block_layer_info.bio_id = bio_id;
  e->block_layer_info.approximate_filemap_start_offset = start_offset;
  e->block_layer_info.approximate_filemap_len = end_offset - start_offset;
  bpf_ringbuf_submit(e, 0);
	return 0;
}

// remap bio/rq 不管
SEC("tp_btf/block_bio_bounce") // 可以很好反映性能的事件，需要额外的数据拷贝和内存申请
int handle_tp6(struct bpf_raw_tracepoint_args *ctx)
{
  if(!block_enable){
    return 0;
  }

	struct bio *bio = (struct bio *)(ctx->args[0]);
  // check bio_ref_map
  // if not exsits, return
  int *bio_ref = bpf_map_lookup_elem(&bio_ref_map, &bio);
  if (bio_ref == NULL) {
    return 0;
  }

  int bio_id = *bio_ref;

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = block__bio_bounce;
  e->info_type = block_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->block_layer_info.bio_id = bio_id;
  bpf_ringbuf_submit(e, 0);
	return 0;
}


SEC("fentry/__rq_qos_track")
int BPF_PROG(trace_rq_qos_track, struct rq_qos *q, struct request *rq, struct bio *bio)
{
  if(!block_enable){
    return 0;
  }

  long long rq_id, bio_id;
  // check bio_ref_map
  // if exsits,  add rq to request_ref_map
  int *bio_ref = bpf_map_lookup_elem(&bio_ref_map, &bio);
  if (bio_ref == NULL) {
    return 0;
  } 

  bio_id = *bio_ref;
  
    // add to request_ref_map
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    rq_id = __sync_fetch_and_add(&global_rq_id, 1); 
    bpf_map_update_elem(&request_ref_map, &rq, &rq_id, BPF_ANY);
  } else {
    rq_id = *request_ref;
    bpf_debug("rq_qos_track:request %lx already in request_ref_map\n",rq);
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = block__bio_add_to_rq;
  e->info_type = block_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->block_layer_info.bio_id = bio_id;
  e->block_layer_info.rq_id = rq_id;
  bpf_ringbuf_submit(e, 0);
	bpf_printk("rq_qos_track target bio: %lx rq: %lx\n", bio, rq);
	return 0;
}

SEC("fentry/__rq_qos_merge") // 代替 block_bio_merge, 用来建立 bio 和 request 的关系
int BPF_PROG(trace_rq_qos_merge, struct rq_qos *q, struct request *rq, struct bio *bio)
{
  if(!block_enable){
    return 0;
  }
  long long rq_id, bio_id;

  int *bio_ref = bpf_map_lookup_elem(&bio_ref_map, &bio);
  if (bio_ref == NULL) {
    return 0;
  } 

  bio_id = *bio_ref;
  
    // add to request_ref_map
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    rq_id = __sync_fetch_and_add(&global_rq_id, 1); 
    bpf_map_update_elem(&request_ref_map, &rq, &rq_id, BPF_ANY);
  } else {
    rq_id = *request_ref;
    bpf_debug("rq_qos_merge:request %lx already in request_ref_map\n",rq);
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = block__bio_add_to_rq;
  e->info_type = block_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->block_layer_info.bio_id = bio_id;
  e->block_layer_info.rq_id = rq_id;
  bpf_ringbuf_submit(e, 0);
	bpf_printk("rq_qos_merge target bio: %lx rq: %lx\n", bio, rq);
  return 0;
}

SEC("fentry/__rq_qos_done_bio") // 代替 block_bio_complete, 用来删除 bio 的引用
int BPF_PROG(trace_rq_qos_done_bio, struct rq_qos *q, struct bio *bio)
{
  if(!block_enable){
    return 0;
  }
  // if bio is in bio_ref_map, delete it
  long long bio_id;
  int *bio_ref = bpf_map_lookup_elem(&bio_ref_map, &bio);
  if (bio_ref == NULL) {
    return 0;
  } else {
    bio_id = *bio_ref;
    bpf_map_delete_elem(&bio_ref_map, &bio);
	  bpf_debug("rq_qos_done_bio target bio: %lx\n", bio);
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  e->event_type = block__bio_done;
  e->info_type = block_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->block_layer_info.bio_id = bio_id;
  e->block_layer_info.rq_id = 0;
  bpf_ringbuf_submit(e, 0);

	return 0;
}

//rq_qos_throttle
SEC("fentry/__rq_qos_throttle") // 可以对性能有观测作用,意味着 bio 走特殊路径
int BPF_PROG(rq_qos_throttle, struct rq_qos *q, struct bio *bio)
{
  if(!block_enable){
    return 0;
  }
  // if bio is not in bio_ref_map, return
  int *bio_ref = bpf_map_lookup_elem(&bio_ref_map, &bio);
  if (bio_ref == NULL) {
    return 0;
  } else {
	  bpf_printk("rq_qos_throttle target  bio: %lx\n", bio);
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  e->event_type = block__bio_throttle;
  e->info_type = block_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->block_layer_info.bio_id = *bio_ref;
  e->block_layer_info.rq_id = 0;
  bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/__rq_qos_done") // 用来代替 block_rq_complete, 用来删除 request 的引用
int BPF_PROG(trace_rq_qos_done, struct rq_qos *q, struct request *rq)
{
  if(!block_enable){
    return 0;
  }
  // if request is in request_ref_map, delete it
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  } else {
    bpf_map_delete_elem(&request_ref_map, &rq);
    bpf_debug("rq_qos_done\n" );
  }

  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }

  e->event_type = block__rq_done;
  e->info_type = block_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->block_layer_info.bio_id = 0;
  e->block_layer_info.rq_id = *request_ref;
  bpf_ringbuf_submit(e, 0);
	bpf_printk("rq_qos_done target rq: %lx\n", rq);
	return 0;
}

SEC("tp_btf/block_rq_issue")
int handle_tp(struct bpf_raw_tracepoint_args *ctx)
{ // ctx->args[0] 是 ptgreg 的指向原触发 tracepoint 的函数的参数， ctx->args[1] 是 tracepoint 定义 trace 函数的第一个参数
  if(!block_enable){
    return 0;
  }
	struct request *rq = (struct request *)(ctx->args[0]);
  long long rq_id;
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  }
  rq_id = *request_ref;
	long nr_bytes = rq->__data_len;
	sector_t sector = rq->__sector;
  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = block__rq_issue;
  e->info_type = block_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->block_layer_info.bio_id = 0;
  e->block_layer_info.rq_id = rq_id;
  e->block_layer_info.sector = sector;
  e->block_layer_info.nr_bytes = nr_bytes;
  bpf_ringbuf_submit(e, 0);
	bpf_printk(" rq_insert target rq: %lx start: %lx len: %lx\n", rq, sector, nr_bytes);
	return 0;
}


// //rq_qos_issue
// SEC("fentry/__rq_qos_issue")
// int BPF_PROG(trace_rq_qos_issue, struct rq_qos *q, struct request *rq)
// {
//   if(!block_enable){
//     return 0;
//   }
//   long long rq_id;
//   int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
//   if (request_ref == NULL) {
//     return 0;
//   }
//   rq_id = *request_ref;
// 	long nr_bytes = rq->__data_len;
// 	sector_t sector = rq->__sector;
//   struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
//   if(e == NULL){
//     return 0;
//   }
//   e->event_type = block__rq_issue;
//   e->info_type = block_layer;
//   e->trigger_type = NOT_PAIR;
//   e->timestamp = bpf_ktime_get_ns();
//   e->block_layer_info.bio_id = 0;
//   e->block_layer_info.rq_id = rq_id;
//   e->block_layer_info.sector = sector;
//   e->block_layer_info.nr_bytes = nr_bytes;
//   bpf_ringbuf_submit(e, 0);
// 	bpf_printk(" rq_insert target rq: %lx start: %lx len: %lx\n", rq, sector, nr_bytes);
// 	return 0;
// }

//rq_qos_requeue
SEC("fentry/__rq_qos_requeue")
int BPF_PROG(trace_rq_qos_requeue, struct rq_qos *q, struct request *rq)
{
  if(!block_enable){
    return 0;
  }
  // check if request is in request_ref_map
  // if not, return
  long long rq_id;
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  } else {
	bpf_printk("rq_qos_requeue target  rq: %lx\n", rq);
  }

  rq_id = *request_ref;
  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = block__rq_requeue;
  e->info_type = block_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->block_layer_info.bio_id = 0;
  e->block_layer_info.rq_id = rq_id;
  bpf_ringbuf_submit(e, 0);
	return 0;
}


/* driver layer */
/* nvme */
SEC("tp_btf/nvme_setup_cmd")
int handle_tp_nvme_1(struct bpf_raw_tracepoint_args *ctx)
{ // ctx->args[0] 是 ptgreg 的指向原触发 tracepoint 的函数的参数， ctx->args[1] 是 tracepoint 定义 trace 函数的第一个参数
  if(!nvme_enable){
    return 0;
  }
	struct request *rq = (struct request *)(ctx->args[0]);
  // check if request is in request_ref_map
  // if not, return
  long long rq_id;
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  } else {
  }
	struct nvme_command *cmd = (struct nvme_command *)(ctx->args[1]);

  rq_id = *request_ref;
  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = nvme__setup_cmd;
  e->info_type = nvme_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->nvme_layer_info.rq_id = rq_id;
  bpf_ringbuf_submit(e, 0);
	bpf_printk("nvme_setup_cmd rq: %llx\n", rq);
	return 0;
}

SEC("tp_btf/nvme_complete_rq")
int handle_tp_nvme_2(struct bpf_raw_tracepoint_args *ctx)
{ 
  if(!nvme_enable){
    return 0;
  }
	struct request *rq = (struct request *)(ctx->args[0]);
  // check if request is in request_ref_map
  // if not, return
  long long rq_id;
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  } else {
  }
  rq_id = *request_ref;
  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = nvme__complete_rq;
  e->info_type = nvme_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->block_layer_info.bio_id = 0;
  e->block_layer_info.rq_id = rq_id;
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("tp_btf/nvme_sq")
int handle_tp_nvme_4(struct bpf_raw_tracepoint_args *ctx)
{ 
  if(!nvme_enable){
    return 0;
  }
	struct request *rq = (struct request *)(ctx->args[0]);
  // check if request is in request_ref_map
  // if not, return
  long long rq_id;
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  } else {
  }
  rq_id = *request_ref;
  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = nvme__sq;
  e->info_type = nvme_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->nvme_layer_info.rq_id = rq_id;
  bpf_ringbuf_submit(e, 0);
  return 0;
}

/* scsi */
SEC("tp_btf/scsi_dispatch_cmd_start")
int handle_tp_scsi_1(struct bpf_raw_tracepoint_args *ctx)
{
  if(!scsi_enable){
    return 0;
  }
	struct scsi_cmnd *cmd = (struct scsi_cmnd *)(ctx->args[0]);
	struct request *rq = cmd_to_rq(cmd);
  // check if request is in request_ref_map
  // if not, return
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  }

  long long rq_id = *request_ref;
  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = scsi__dispatch_cmd_start;
  e->info_type = scsi_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->scsi_layer_info.rq_id = rq_id;
  bpf_ringbuf_submit(e, 0);

	bpf_printk("scsi_dispatch_cmd_start rq: %lx\n", (unsigned long)rq);
	return 0;
}

SEC("tp_btf/scsi_dispatch_cmd_error")
int handle_tp_scsi_2(struct bpf_raw_tracepoint_args *ctx)
{
  if(!scsi_enable){
    return 0;
  }
	struct scsi_cmnd *cmd = (struct scsi_cmnd *)(ctx->args[0]);
	struct request *rq = cmd_to_rq(cmd);
  // check if request is in request_ref_map
  // if not, return
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  } else {
  }
  
  long long rq_id = *request_ref;
  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = scsi__dispatch_cmd_error;
  e->info_type = scsi_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->scsi_layer_info.rq_id = rq_id;
  bpf_ringbuf_submit(e, 0);
	bpf_printk("scsi_dispatch_cmd_error rq: %lx\n", (unsigned long)rq);
	return 0;
}

SEC("tp_btf/scsi_dispatch_cmd_done")
int handle_tp_scsi_3(struct bpf_raw_tracepoint_args *ctx)
{
  if(!scsi_enable){
    return 0;
  }
	struct scsi_cmnd *cmd = (struct scsi_cmnd *)(ctx->args[0]);
	struct request *rq = cmd_to_rq(cmd);
  // check if request is in request_ref_map
  // if not, return
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  } else {
  }

  long long rq_id = *request_ref;
  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = scsi__dispatch_cmd_done;
  e->info_type = scsi_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->scsi_layer_info.rq_id = rq_id;
  bpf_ringbuf_submit(e, 0);

	bpf_printk("scsi_dispatch_cmd_done rq: %lx\n", (unsigned long)rq);

	return 0;
}

SEC("tp_btf/scsi_dispatch_cmd_timeout")
int handle_tp_scsi_4(struct bpf_raw_tracepoint_args *ctx)
{
  if(!scsi_enable){
    return 0;
  }
	struct scsi_cmnd *cmd = (struct scsi_cmnd *)(ctx->args[0]);
	struct request *rq = cmd_to_rq(cmd);
  // check if request is in request_ref_map
  // if not, return
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  }
  long long rq_id = *request_ref;
  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = scsi__dispatch_cmd_timeout;
  e->info_type = scsi_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->scsi_layer_info.rq_id = rq_id;
  bpf_ringbuf_submit(e, 0);
  bpf_printk("scsi_dispatch_cmd_timeout rq: %lx\n", (unsigned long)rq);
	return 0;
}
/* virtio-blk */

// SEC("fentry/virt")
// int BPF_PROG(virtblk_done)
// 	bpf_printk("virtblk_request_done\n");
// 	return 0;
// }
SEC("fentry/virtio_queue_rq")
int BPF_PROG(virtio_queue_rq, struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
  if(!virtio_enable){
    return 0;
  }
	struct request *rq = bd->rq;
  // check if request is in request_ref_map
  // if not, return
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  } else {
  }
	long long sector = rq->__sector;
	unsigned long nr_bytes = rq->__data_len << 9;
  dev_t dev = rq->rq_disk->major << 20 | rq->rq_disk->first_minor;

  long long rq_id = *request_ref;
  struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
  if(e == NULL){
    return 0;
  }
  e->event_type = virtio__queue_rq;
  e->info_type = virtio_layer;
  e->trigger_type = NOT_PAIR;
  e->timestamp = bpf_ktime_get_ns();
  e->virtio_layer_info.rq_id = rq_id;
  e->virtio_layer_info.dev = dev;
  bpf_ringbuf_submit(e, 0);
	return 0;
}

