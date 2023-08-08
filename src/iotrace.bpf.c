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

#ifdef DEBUG
#define bpf_debug(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define bpf_debug(fmt, ...)
#endif

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
  __type(key, ino_t);
  __type(value, int);
} inode_ref_map SEC(".maps");

// a map to store how many processes are referring to a file
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, ino_t);
} fd_ref_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, int);
} fd_filted_map SEC(".maps");


// bio refference map
// if the bio is not in the map, it means no process is referring to it
// if the bio is in the map, it means there are some processes are referring
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct bio *);
  __type(value, int);
} bio_ref_map SEC(".maps");

// request refference map
// if the request is not in the map, it means no process is referring to it
// if the request is in the map, it means there are some processes are referring
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct request *);
  __type(value, int);
} request_ref_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
} rb SEC(".maps");

struct filter_config {
  unsigned int tgid;
  unsigned int tid;
  unsigned long long inode;
  unsigned long long directory_inode;
  unsigned long dev;
  u8 filter_by_command;
  char command[MAX_COMM_LEN];
  unsigned int command_len;
  unsigned long long cgroup_id;
} filter_config = {
    .tgid = 0,
    .tid = 0,
    .inode = 0,
    .directory_inode = 0,
    .dev = 0,
    .command_len = 0,
    .filter_by_command = 0,
    .cgroup_id = 0,
};

u8 qemu_enable = 1;
u8 syscall_enable = 1;
u8 vfs_enable = 1;
u8 block_enable = 1;
u8 scsi_enable = 1;
u8 nvme_enable = 1;
u8 ext4_enable = 1;
u8 filemap_enable = 1;
u8 iomap_enable = 1;
u8 sched_enable = 1;
u8 virtio_enable = 1;

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

static inline void set_common_info(struct event *task_info, pid_t tgid,
                                   pid_t tid, enum kernel_hook_type event_type,
                                   enum info_type info_type) {
  task_info->pid = tgid;
  task_info->tid = tid;
  task_info->event_type = event_type;
  task_info->info_type = info_type;
  task_info->timestamp = bpf_ktime_get_ns();
}

static inline void set_fs_info(struct event *task_info, ino_t inode,
                               ino_t dir_inode, dev_t dev,
                               unsigned long long file_offset,
                               unsigned long long file_bytes) {
  task_info->vfs_layer_info.inode = inode;
  task_info->vfs_layer_info.file_offset = file_offset;
  task_info->vfs_layer_info.file_bytes = file_bytes;
  task_info->vfs_layer_info.dev = dev;
  task_info->vfs_layer_info.dir_inode = dir_inode;
}

int inline pid_filter(pid_t tgid, pid_t tid) {
  // assert(filter_config.tgid != 0 || filter_config.tid != 0); !
  if (filter_config.tgid != tgid) {
    return 1;
  }
  if (filter_config.tid != 0 && filter_config.tid != tid) {
    return 1;
  }
  return 0;
}

int inline get_and_filter_pid(pid_t *tgid, pid_t *tid) {
  u64 id = bpf_get_current_pid_tgid();
  *tgid = id >> 32;
  *tid = id & 0xffffffff;
  return pid_filter(*tgid, *tid);
}


int inline filter_inode_dev_dir(struct inode* iinode,struct file* file,ino_t* inode,dev_t* devp,ino_t* dir_inodep){
  *inode = BPF_CORE_READ(iinode, i_ino);
  if(filter_config.inode != 0 && filter_config.inode != *inode){
    return 1;
  }
  if(filter_config.dev != 0){
    dev_t dev = BPF_CORE_READ(iinode, i_sb, s_dev);
    if(filter_config.dev != dev){
      return 1;
    }
    *devp = dev;
  }

  if(filter_config.directory_inode != 0){
    struct path p = BPF_CORE_READ(file, f_path);
	  ino_t dir_ino = BPF_CORE_READ(p.dentry, d_inode, i_ino);
    if(filter_config.directory_inode != dir_ino){
      return 1;
    }
    *dir_inodep = dir_ino;
  }
  return 0;
}


// TODO: 如果遇到一些不属于追踪范围的请求，可能已经判断过不属于追踪范围，但是还是会被追踪
// 由于已经通过 pid 过滤了，所以这种情况出现的请求对应的文件描述符可能不会太多
// 所以通过一个 map 来记录一下，作为短路判断
// FIXME: 通过追踪文件描述符的开启和回收来维护这个 map
int inline update_fd_inode_map_and_filter_dev_inode_dir(int fd,ino_t* inodep,dev_t* devp,ino_t* dir_inodep) {
  int *fd_ref = bpf_map_lookup_elem(&fd_ref_map, &fd);
  int ret = 0;
  ino_t inode = 0;
  dev_t dev = 0;
  ino_t dir_inode = 0;
  if (fd_ref == NULL) {
    if(filter_config.dev != 0 || filter_config.inode != 0 || filter_config.directory_inode != 0){
      // if fd has been filtered, return 1
      int *fd_filted = bpf_map_lookup_elem(&fd_filted_map, &fd);
      if (fd_filted != NULL) {
        return 1;
      }
    }
    

    struct task_struct *task = bpf_get_current_task_btf();
    struct files_struct *files = task->files;
    struct fdtable *fdt;
    struct file **fdd;
    struct file *file;
    fdt = files->fdt;
    fdd = fdt->fd;
    bpf_core_read(&file, sizeof(struct file *), fdd + fd);
    struct inode* iinode = BPF_CORE_READ(file, f_inode);
    // filter and update filterd fd map
    ret = filter_inode_dev_dir(iinode,file,&inode,&dev,&dir_inode);
    if(ret){
      bpf_map_update_elem(&fd_filted_map, &fd, &fd, BPF_ANY);
      return 1;
    }

    // update inode_ref_map
    int *inode_ref = bpf_map_lookup_elem(&inode_ref_map, &inode);
    if (inode_ref == NULL) {
      bpf_map_update_elem(&inode_ref_map, &inode, &fd, BPF_ANY);
    }
    bpf_map_update_elem(&fd_ref_map, &fd, &inode, BPF_ANY);
  }
  if(inodep != NULL)
    *inodep = inode;
  if(devp != NULL)
    *devp = dev;
  if(dir_inodep != NULL)
    *dir_inodep = dir_inode;
  
  return 0;
}

/* read_write syscall  read_write.c */
// read_enter/exit
SEC("ksyscall/read")
int BPF_KPROBE_SYSCALL(read, int fd, void *buf, size_t count) {
  if (!syscall_enable) {
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd,NULL,NULL,NULL);
  if(ret){
    return 0;
  }
  // TODO:

  bpf_printk("read enter: fd %d buf %lx count %lu\n", fd, buf, count);
  return 0;
}
// wirte_enter/exit
SEC("ksyscall/write")
int BPF_KPROBE_SYSCALL(write, int fd, void *buf, size_t count) {
  if (!syscall_enable) {
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
    int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd,NULL,NULL,NULL);
  if(ret){
    return 0;
  }
  bpf_printk("write enter: fd %d buf %lx count %lu\n", fd, buf, count);
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

    int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd,NULL,NULL,NULL);
  if(ret){
    return 0;
  }

  bpf_printk("pread64 enter: fd %d count %lu offset %lu\n", fd, count, offset);
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

    int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd,NULL,NULL,NULL);
  if(ret){
    return 0;
  }

  bpf_printk("pwrite64 enter: fd %d count %lu offset %lu\n", fd, count, offset);
  return 0;
}
// readv_enter/exit
SEC("ksyscall/readv")
int BPF_KPROBE_SYSCALL(readv, int fd, struct iovec *vec, unsigned long vlen) {
  if (!syscall_enable) {
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

    int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd,NULL,NULL,NULL);
  if(ret){
    return 0;
  }
  bpf_printk("readv enter: fd %d vec %lx vlen %lu\n", fd, vec, vlen);
  return 0;
}
// writev_enter/exit
SEC("ksyscall/writev")
int BPF_KPROBE_SYSCALL(writev, int fd, struct iovec *vec, unsigned long vlen) {
  if (!syscall_enable) {
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

    int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd,NULL,NULL,NULL);
  if(ret){
    return 0;
  }
  bpf_printk("writev enter: fd %d vec %lx vlen %lu\n", fd, vec, vlen);
  return 0;
}
// preadv_enter/exit
SEC("ksyscall/preadv")
int BPF_KPROBE_SYSCALL(preadv, int fd, struct iovec *vec, unsigned long vlen,
                       loff_t offset) {

  if (!syscall_enable) {
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

    int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd,NULL,NULL,NULL);
  if(ret){
    return 0;
  }
  bpf_printk("preadv enter: fd %d vec %lx vlen %lu\n", fd, vec, vlen);
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

    int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd,NULL,NULL,NULL);
  if(ret){
    return 0;
  }
  bpf_printk("pwritev enter: fd %d vec %lx vlen %lu\n", fd, vec, vlen);
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

    int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd,NULL,NULL,NULL);
  if(ret){
    return 0;
  }
  bpf_printk("fsync enter: fd %d\n", fd);
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

    int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd,NULL,NULL,NULL);
  if(ret){
    return 0;
  }
  bpf_printk("fdatasync enter: fd %d\n", fd);
  return 0;
}

// sync_file_range
SEC("ksyscall/sync_file_range")
int BPF_KPROBE_SYSCALL(sync_file_range, int fd, loff_t offset, loff_t nbytes,
                       unsigned int flags) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

    int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd,NULL,NULL,NULL);
  if(ret){
    return 0;
  }
  bpf_printk("sync_file_range enter: fd %d offset %lu nbytes %lu \n", fd,
             offset, nbytes);
  return 0;
}


/* vfs layer */

int inline vfs_filter_inode(ino_t inode){
  if(filter_config.inode != 0 && filter_config.inode != inode){
    return 1;
  }
  // check inode_ref_map
  int *inode_ref = bpf_map_lookup_elem(&inode_ref_map, &inode);
  if (inode_ref == NULL) {
    return 1;
  }

  return 0;
}

// 对于 vfs 层的挂载点，由于是完全同步的，所以直接通过 pid 过滤即可
// 传回用户态时，如果前置 syscall 没有出现，那么把事件丢弃
// 也需要通过 inode 过滤 ，因为内核态查 map 的开销相对小 TODO:
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
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  unsigned long nr_bytes = iter->count;
  loff_t *pos = NULL;
  loff_t offset = 0;
  bpf_core_read(&pos, sizeof(pos), ctx + 2);
  bpf_core_read(&offset, sizeof(offset), pos);


  // bpf_printk("do_iter_read enter:	ino %lu offset %lu len %lu\n", ino, offset, nr_bytes);
  return 0;
}
SEC("fexit/do_iter_read")
int BPF_PROG(trace_do_iter_read_exit, struct file *file) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }

  // bpf_printk("do_iter_read exit:	ino %lu\n", ino);
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
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  unsigned long nr_bytes = iter->count;
  loff_t *pos = NULL;
  loff_t offset = 0;
// pos 参数是一个 loff_t * 类型的指针
// 导致 ctx 本身是一个二级指针，并且 pos 本身不是结构体，
// BPF 对二级指针的支持不是很好，所以这里需要使用 bpf_core_read
  bpf_core_read(&pos, sizeof(pos), ctx + 2);
  bpf_core_read(&offset, sizeof(offset), pos);
  return 0;
}
SEC("fexit/do_iter_write")
int BPF_PROG(trace_do_iter_write_exit, struct file *file) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  // bpf_printk("do_iter_write exit:	ino %lu\n", ino);
  return 0;
}
// vfs_iocb_iter_write
SEC("fentry/vfs_iocb_iter_write")
int BPF_PROG(trace_vfs_iocb_iter_write, struct file *file, struct kiocb *iocb,
             struct iov_iter *iter) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  struct inode *inode = file->f_inode;
  unsigned long nr_bytes = iter->count;
  loff_t offset = iocb->ki_pos;
  bpf_printk("vfs_iocb_iter_write enter:	ino %lu offset %lu len %lu\n",
             ino, offset, nr_bytes);
  return 0;
}
SEC("fexit/vfs_iocb_iter_write")
int BPF_PROG(trace_vfs_iocb_iter_write_exit, struct file *file,
             struct kiocb *iocb, struct iov_iter *iter, ssize_t ret) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  struct inode *inode = file->f_inode;
  bpf_printk("vfs_iocb_iter_write exit:	ino %lu\n", ino);
  return 0;
}
// vfs_iocb_iter_read
SEC("fentry/vfs_iocb_iter_read")
int BPF_PROG(trace_vfs_iocb_iter_read, struct file *file, struct kiocb *iocb,
             struct iov_iter *iter) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  struct inode *inode = file->f_inode;
  unsigned long nr_bytes = iter->count;
  loff_t offset = iocb->ki_pos;
  bpf_printk("vfs_iocb_iter_read enter:	ino %lu offset %lu len %lu\n", ino,
             offset, nr_bytes);
  return 0;
}
SEC("fexit/vfs_iocb_iter_read")
int BPF_PROG(trace_vfs_iocb_iter_read_exit, struct file *file,
             struct kiocb *iocb, struct iov_iter *iter, ssize_t ret) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  bpf_printk("vfs_iocb_iter_read exit:	ino %lu\n", ino);
  return 0;
}
// vfs_read
SEC("fentry/vfs_read")
int BPF_PROG(trace_vfs_read, struct file *file, char *buf, size_t count) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  unsigned long nr_bytes = count;
  loff_t *pos = NULL;
  loff_t offset = 0;
  bpf_core_read(&pos, sizeof(pos), ctx + 2);
  bpf_core_read(&offset, sizeof(offset), pos);
  bpf_printk("vfs_read enter:	ino %lu offset %lu len %lu\n", ino, offset,
             nr_bytes);
  return 0;
}
SEC("fexit/vfs_read")
int BPF_PROG(trace_vfs_read_exit, struct file *file, char *buf, size_t count) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  bpf_printk("vfs_read exit:	ino %lu\n", ino);
  return 0;
}
// vfs_write
SEC("fentry/vfs_write")
int BPF_PROG(trace_vfs_write, struct file *file, char *buf, size_t count) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  unsigned long nr_bytes = count;
  loff_t *pos = NULL;
  loff_t offset = 0;
  bpf_core_read(&pos, sizeof(pos), ctx + 2);
  bpf_core_read(&offset, sizeof(offset), pos);
  bpf_printk("vfs_write enter:	ino %lu offset %lu len %lu\n", ino, offset,
             nr_bytes);
  return 0;
}
SEC("fexit/vfs_write")
int BPF_PROG(trace_vfs_write_exit, struct file *file, char *buf, size_t count) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  bpf_printk("vfs_write exit:	ino %lu\n", ino);
  return 0;
}

SEC("fentry/vfs_fsync_range")
int BPF_PROG(trace_vfs_fsync_range, struct file *file, loff_t start, loff_t end,
             int datasync) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }

  return 0;
}

// generic_file_read_iter
SEC("fentry/generic_file_read_iter")
int BPF_PROG(trace_generic_file_read_iter, struct kiocb *iocb,
             struct iov_iter *iter) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  struct file *file = iocb->ki_filp;
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  loff_t offset = iocb->ki_pos;
  unsigned long nr_bytes = iter->count;
  bpf_printk("generic_file_read_iter enter:	ino %lu offset %lu len %lu\n",
             ino, offset, nr_bytes);
  return 0;
}
SEC("fexit/generic_file_read_iter")
int BPF_PROG(trace_generic_file_read_iter_exit, struct kiocb *iocb,
             struct iov_iter *iter, ssize_t ret) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  struct file *file = iocb->ki_filp;
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  return 0;
}
// generic_file_write_iter
SEC("fentry/generic_file_write_iter")
int BPF_PROG(trace_generic_file_write_iter, struct kiocb *iocb,
             struct iov_iter *iter) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  struct file *file = iocb->ki_filp;
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  loff_t offset = iocb->ki_pos;
  unsigned long nr_bytes = iter->count;
  bpf_printk("generic_file_write_iter enter:	ino %lu offset %lu len %lu\n",
             ino, offset, nr_bytes);
  return 0;
}
SEC("fexit/generic_file_write_iter")
int BPF_PROG(trace_generic_file_write_iter_exit, struct kiocb *iocb,
             struct iov_iter *iter, ssize_t ret) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  struct file *file = iocb->ki_filp;
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  return 0;
}

// filemap_get_pages
SEC("fentry/filemap_get_pages")
int BPF_PROG(trace_filemap_get_pages, struct kiocb *iocb,
             struct iov_iter *iter) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  struct file *file = iocb->ki_filp;
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  loff_t offset = iocb->ki_pos;
  unsigned long nr_bytes = iter->count;
  bpf_printk("filemap_get_pages enter:	ino %lu offset %lu len %lu\n", ino,
             offset, nr_bytes);
  return 0;
}

SEC("fexit/filemap_get_pages")
int BPF_PROG(trace_filemap_get_pages_exit, struct kiocb *iocb,
             struct iov_iter *iter, ssize_t ret) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  struct file *file = iocb->ki_filp;
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  return 0;
}

// file_write_and_wait_range
SEC("fentry/file_write_and_wait_range")
int BPF_PROG(trace_file_write_and_wait_range, struct file *file, loff_t start,
             loff_t end) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  bpf_printk("file_write_and_wait_range:	ino %lu start %lu end %lu\n",
             ino, start, end);
  return 0;
}

/* iomap */
// iomap_dio_rw
SEC("fentry/iomap_dio_rw")
int BPF_PROG(trace_enter_iomap_dio_rw, struct kiocb *iocb,
             struct iov_iter *iter) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  struct file *file = iocb->ki_filp;
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }

  return 0;
}
SEC("fexit/iomap_dio_rw")
int BPF_PROG(trace_exit_iomap_dio_rw, struct kiocb *iocb, struct iov_iter *iter,
             ssize_t ret) {
  if(!vfs_enable){
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  struct file *file = iocb->ki_filp;
  ino_t ino = file->f_inode->i_ino;
  if(vfs_filter_inode(ino)){
    return 0;
  }
  return 0;
}

SEC("tp_btf/sched_switch")
int handle_tp_sched_1(struct bpf_raw_tracepoint_args *ctx) {
  struct task_struct *prev = (struct task_struct *)(ctx->args[0]);
  struct task_struct *next = (struct task_struct *)(ctx->args[1]);
  pid_t prev_pid = BPF_CORE_READ(prev, pid);
  pid_t next_pid = BPF_CORE_READ(next, pid);
  bpf_printk("sched_switch target prev_pid: %d next_pid: %d\n", prev_pid,
             next_pid);
  return 0;
}

/* page cache */
SEC("tp_btf/mm_filemap_delete_from_page_cache")
int handle_tp_filemap_1(struct bpf_raw_tracepoint_args *ctx) {
  struct page *page = (struct page *)(ctx->args[0]);
  struct address_space *mapping = page->mapping;
  struct inode *inode = mapping->host;
  ino_t ino = inode->i_ino;
  unsigned long index = page->index;
  bpf_printk(
      "filemap_delete_from_page_cache target inode: %lx ino: %ld index: %ld\n",
      inode, ino, index);
  return 0;
}

SEC("tp_btf/mm_filemap_add_to_page_cache")
int handle_tp_filemap_2(struct bpf_raw_tracepoint_args *ctx) {
  struct page *page = (struct page *)(ctx->args[0]);
  struct address_space *mapping = page->mapping;
  struct inode *inode = mapping->host;
  ino_t ino = inode->i_ino;
  unsigned long index = page->index;
  bpf_printk(
      "filemap_add_to_page_cache target inode: %lx ino: %ld index: %ld\n",
      inode, ino, index);
  return 0;
}

// void wait_on_page_writeback(struct page *page)
SEC("fentry/wait_on_page_writeback")
int BPF_PROG(trace_wait_on_page_writeback, struct page *page) {
  struct address_space *mapping = page->mapping;
  struct inode *inode = mapping->host;
  ino_t ino = inode->i_ino;
  unsigned long index = page->index;
  bpf_printk("wait_on_page_writeback target inode: %lx ino: %ld index: %ld\n",
             inode, ino, index);
  return 0;
}

SEC("fentry/vfs_read")
// int BPF_PROG(enter_vfs_read, struct file* file, char *buf, size_t count,
// loff_t *pos){
int BPF_PROG(enter_vfs_read) {
  // 1. get info from incoming function
  struct file *file = (struct file *)(ctx + 0);
  if (file->f_op->read_iter == NULL) {
    return 0;
  }
  size_t count = (size_t)(ctx + 2);
  loff_t *pos = (loff_t *)(ctx + 3);

  u64 id = bpf_get_current_pid_tgid();
  u64 cgid = bpf_get_current_cgroup_id();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;

  // 2. if the event must be dropped
  if (filter_config.filter_by_command == 1) {
    char comm[MAX_COMM_LEN];
    bpf_get_current_comm(&comm, MAX_COMM_LEN);
    if (task_comm_dropable(comm)) {
      return 0;
    }
  }
  if (filter_config.tgid != 0 && filter_config.tgid != tgid) {
    return 0;
  }
  if (filter_config.tid != 0 && filter_config.tid != tid) {
    return 0;
  }
  if (filter_config.cgroup_id != 0 && filter_config.cgroup_id != cgid) {
    return 0;
  }

  // 3. get info from file
  struct inode *inode = file->f_inode;
  struct path p = file->f_path;
  ino_t i_inop = p.dentry->d_parent->d_inode->i_ino;
  ino_t i_ino = inode->i_ino;
  dev_t dev = inode->i_sb->s_dev;
  if (filter_config.dev != 0 && filter_config.dev != dev) {
    return 0;
  }
  if (filter_config.directory_inode != 0 &&
      filter_config.directory_inode != i_inop) {
    return 0;
  }
  if (filter_config.inode != 0 && filter_config.inode != i_ino) {
    return 0;
  }

  // 4. update inode_ref_map
  int *ref = bpf_map_lookup_elem(&inode_ref_map, &i_ino);
  if (ref == NULL) {
    int a = 1;
    bpf_map_update_elem(&inode_ref_map, &i_ino, &a, BPF_ANY);
  } else {
    (*ref)++;
  }

  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    __sync_add_and_fetch(&dropped, 1);
    return 0;
  }
  set_common_info(task_info, tgid, tid, vfs_read_enter, vfs_layer);
  loff_t offset = *pos;
  set_fs_info(task_info, i_ino, i_inop, dev, offset, count);
  bpf_ringbuf_submit(task_info, BPF_RB_NO_WAKEUP);
  return 0;
}

SEC("fexit/vfs_read")
// int BPF_PROG(exit_vfs_read, struct file* file, char *buf, size_t count,
// loff_t *pos ){
int BPF_PROG(exit_vfs_read) {
  struct file *file = NULL;
  size_t count = 0;
  loff_t *pos = NULL;
  long ret = 0;
  bpf_probe_read(&ret, sizeof(long), ctx + 4);
  bpf_probe_read(&file, sizeof(struct file *), ctx + 0);
  bpf_probe_read(&count, sizeof(size_t), ctx + 2);
  bpf_probe_read(&pos, sizeof(loff_t *), ctx + 3);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  struct path p = BPF_CORE_READ(file, f_path);
  ino_t i_inop = BPF_CORE_READ(p.dentry, d_parent, d_inode, i_ino);
  ino_t i_ino = BPF_CORE_READ(inode, i_ino);
  dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
  if (common_filter(tid, tgid, dev, i_ino, 0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_dropable(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, vfs_read_exit, vfs_layer);
  loff_t offset = 0;
  if (pos != NULL) {
    bpf_probe_read(&offset, sizeof(loff_t), pos);
    if ((long long)offset - ret >= 0) {
      offset -= ret;
    }
  }
  set_fs_info(task_info, i_ino, 0, dev, offset, count);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fentry/filemap_get_pages")
int BPF_PROG(enter_filemap_get_pages, struct kiocb *iocb, struct iov_iter *iter,
             struct pagevec *pvec) {
  struct file *file = BPF_CORE_READ(iocb, ki_filp);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  struct path p = BPF_CORE_READ(file, f_path);
  ino_t i_inop = BPF_CORE_READ(p.dentry, d_parent, d_inode, i_ino);
  ino_t i_ino = BPF_CORE_READ(inode, i_ino);
  dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
  if (common_filter(tid, tgid, 0, i_ino, 0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_dropable(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, filemap_get_pages_enter, vfs_layer);
  loff_t offset = BPF_CORE_READ(iocb, ki_pos);
  unsigned long count = BPF_CORE_READ(iter, count);
  set_fs_info(task_info, i_ino, 0, 0, offset, count);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fexit/filemap_get_pages")
int BPF_PROG(exit_filemap_get_pages, struct kiocb *iocb, struct iov_iter *iter,
             struct pagevec *pvec) {
  struct file *file = BPF_CORE_READ(iocb, ki_filp);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  struct path p = BPF_CORE_READ(file, f_path);
  ino_t i_inop = BPF_CORE_READ(p.dentry, d_parent, d_inode, i_ino);
  ino_t i_ino = BPF_CORE_READ(inode, i_ino);
  dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
  if (common_filter(tid, tgid, 0, i_ino, 0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_dropable(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, filemap_get_pages_exit, vfs_layer);
  loff_t offset = BPF_CORE_READ(iocb, ki_pos);
  unsigned long count = BPF_CORE_READ(iter, count);
  set_fs_info(task_info, i_ino, 0, 0, offset, count);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fentry/mark_page_accessed")
int BPF_PROG(trace_mark_page_accessed, struct page *page) {
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  struct inode *inode = BPF_CORE_READ(page, mapping, host);
  ino_t i_ino = BPF_CORE_READ(inode, i_ino);
  dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
  if (common_filter(tid, tgid, 0, i_ino, 0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_dropable(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, mark_page_accessed, vfs_layer);
  loff_t alloffset = (BPF_CORE_READ(page, index) << 12);
  set_fs_info(task_info, i_ino, 0, 0, alloffset, 4096);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}
SEC("fentry/filemap_write_and_wait_range")
int BPF_PROG(trace_enter_filemap_write_and_wait_range,
             struct address_space *mapping, loff_t start_byte,
             loff_t end_byte) {
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  struct inode *inode = BPF_CORE_READ(mapping, host);
  ino_t i_ino = BPF_CORE_READ(inode, i_ino);
  // dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
  if (common_filter(tid, tgid, 0, i_ino, 0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_dropable(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, filemap_write_and_wait_range_enter,
                  vfs_layer);
  set_fs_info(task_info, i_ino, 0, 0, start_byte, end_byte + 1 - start_byte);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fexit/filemap_write_and_wait_range")
int BPF_PROG(trace_exit_filemap_write_and_wait_range,
             struct address_space *mapping, loff_t start_byte,
             loff_t end_byte) {
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  struct inode *inode = BPF_CORE_READ(mapping, host);
  ino_t i_ino = BPF_CORE_READ(inode, i_ino);
  // dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
  if (common_filter(tid, tgid, 0, i_ino, 0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_dropable(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, filemap_write_and_wait_range_exit,
                  vfs_layer);
  set_fs_info(task_info, i_ino, 0, 0, start_byte, end_byte + 1 - start_byte);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fentry/filemap_range_needs_writeback")
int BPF_PROG(trace_enter_filemap_range_needs_writeback,
             struct address_space *mapping, loff_t start_byte,
             loff_t end_byte) {
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  struct inode *inode = BPF_CORE_READ(mapping, host);
  ino_t i_ino = BPF_CORE_READ(inode, i_ino);
  // dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
  if (common_filter(tid, tgid, 0, i_ino, 0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_dropable(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, filemap_range_needs_writeback_enter,
                  vfs_layer);
  set_fs_info(task_info, i_ino, 0, 0, start_byte, end_byte + 1 - start_byte);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fexit/filemap_range_needs_writeback")
int BPF_PROG(trace_exit_filemap_range_needs_writeback,
             struct address_space *mapping, loff_t start_byte,
             loff_t end_byte) {
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  struct inode *inode = BPF_CORE_READ(mapping, host);
  ino_t i_ino = BPF_CORE_READ(inode, i_ino);
  dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
  if (common_filter(tid, tgid, 0, i_ino, 0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_dropable(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, filemap_range_needs_writeback_exit,
                  vfs_layer);
  set_fs_info(task_info, i_ino, 0, 0, start_byte, end_byte + 1 - start_byte);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fentry/iomap_dio_rw")
int BPF_PROG(trace_enter_iomap_dio_rw, struct kiocb *iocb,
             struct iov_iter *iter) {
  struct file *file = BPF_CORE_READ(iocb, ki_filp);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  struct path p = BPF_CORE_READ(file, f_path);
  ino_t i_inop = BPF_CORE_READ(p.dentry, d_parent, d_inode, i_ino);
  ino_t i_ino = BPF_CORE_READ(inode, i_ino);
  dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
  if (common_filter(tid, tgid, 0, i_ino, 0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_dropable(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, filemap_get_pages_enter, vfs_layer);
  loff_t offset = BPF_CORE_READ(iocb, ki_pos);
  unsigned long count = BPF_CORE_READ(iter, count);
  set_fs_info(task_info, i_ino, 0, 0, offset, count);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fexit/iomap_dio_rw")
int BPF_PROG(trace_exit_iomap_dio_rw, struct kiocb *iocb,
             struct iov_iter *iter) {
  struct file *file = BPF_CORE_READ(iocb, ki_filp);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  struct path p = BPF_CORE_READ(file, f_path);
  ino_t i_inop = BPF_CORE_READ(p.dentry, d_parent, d_inode, i_ino);
  ino_t i_ino = BPF_CORE_READ(inode, i_ino);
  dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
  if (common_filter(tid, tgid, 0, i_ino, 0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_dropable(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, filemap_get_pages_enter, vfs_layer);
  loff_t offset = BPF_CORE_READ(iocb, ki_pos);
  unsigned long count = BPF_CORE_READ(iter, count);
  set_fs_info(task_info, i_ino, 0, 0, offset, count);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fentry/__cond_resched")
int BPF_PROG(trace_enter___cond_resched) {
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  if (common_filter(tid, tgid, 0, 0, 0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_dropable(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, __cond_resched_enter, vfs_layer);
  set_fs_info(task_info, 0, 0, 0, 0, 0);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fexit/__cond_resched")
int BPF_PROG(trace_exit___cond_resched) {
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  if (common_filter(tid, tgid, 0, 0, 0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_dropable(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, __cond_resched_exit, vfs_layer);
  set_fs_info(task_info, 0, 0, 0, 0, 0);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fentry/vfs_write")
int BPF_PROG(enter_vfs_write) {
  struct file *file = NULL;
  size_t count = 0;
  loff_t *pos = NULL;
  bpf_probe_read(&file, sizeof(struct file *), ctx + 0);
  if (BPF_CORE_READ(file, f_op, write_iter) == NULL) {
    return 0;
  }
  bpf_probe_read(&count, sizeof(size_t), ctx + 2);
  bpf_probe_read(&pos, sizeof(loff_t *), ctx + 3);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  struct path p = BPF_CORE_READ(file, f_path);
  ino_t i_inop = BPF_CORE_READ(p.dentry, d_parent, d_inode, i_ino);
  ino_t i_ino = BPF_CORE_READ(inode, i_ino);
  dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
  if (common_filter(tid, tgid, 0, i_ino, 0)) {
    return 0;
  }

  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_dropable(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  if (bpf_map_lookup_elem(&ino_path_map, &i_ino) == NULL) {
    if (!read_and_store_abs_path(&p, &i_ino,
                                 BPF_CORE_READ(inode, i_sb, s_bdev))) {
      goto go_on;
    }
  }
go_on:;
  set_common_info(task_info, tgid, tid, vfs_write_enter, vfs_layer);
  loff_t offset = 0;
  bpf_probe_read(&offset, sizeof(loff_t), pos);
  set_fs_info(task_info, i_ino, 0, 0, offset, count);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fexit/vfs_write")
int BPF_PROG(exit_vfs_write) {
  struct file *file = NULL;
  size_t count = 0;
  loff_t *pos = NULL;
  long ret = 0;
  bpf_probe_read(&ret, sizeof(long), ctx + 4);
  bpf_probe_read(&file, sizeof(struct file *), ctx + 0);
  bpf_probe_read(&count, sizeof(size_t), ctx + 2);
  bpf_probe_read(&pos, sizeof(loff_t *), ctx + 3);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  struct path p = BPF_CORE_READ(file, f_path);
  ino_t i_inop = BPF_CORE_READ(p.dentry, d_parent, d_inode, i_ino);
  ino_t i_ino = BPF_CORE_READ(inode, i_ino);
  dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
  if (common_filter(tid, tgid, 0, i_ino, 0)) {
    return 0;
  }

  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_dropable(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, vfs_write_exit, vfs_layer);
  loff_t offset = 0;
  if (pos != NULL) {
    bpf_probe_read(&offset, sizeof(loff_t), pos);
    if ((long long)offset - ret >= 0) {
      offset -= ret;
    }
  }
  set_fs_info(task_info, i_ino, 0, 0, offset, count);
  bpf_ringbuf_submit(task_info, 0);
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

static inline void set_rq_comm_info(struct event *task_info, struct request *rq,
                                    dev_t dev) {
  task_info->rq_info.dev = dev;
  task_info->rq_info.rq = (unsigned long long)rq;
  task_info->rq_info.request_queue = (unsigned long long)BPF_CORE_READ(rq, q);
}

static inline void set_common_bio_info(struct event *task_info, struct bio *bio,
                                       dev_t dev) {
  task_info->bio_info.bio = (unsigned long long)bio;
  task_info->bio_info.dev = dev;
  task_info->bio_info.bio_info_type = comm_bio;
  struct bvec_iter bi_iter = BPF_CORE_READ(bio, bi_iter);
  task_info->bio_info.bvec_idx_start = bi_iter.bi_idx;
  struct bio *parent_bio = BPF_CORE_READ(bio, bi_private);
  bi_iter = BPF_CORE_READ(parent_bio, bi_iter);
  task_info->bio_info.bvec_idx_end = bi_iter.bi_idx;
}

SEC("raw_tp/block_rq_complete")
int raw_tracepoint__block_rq_complete(struct bpf_raw_tracepoint_args *ctx) {
  struct request *rq = (struct request *)(ctx->args[0]);
  int error = (int)(ctx->args[1]);
  unsigned int nr_bytes = (unsigned int)(ctx->args[2]);
  int bio_cnt = 0;
  struct bio *bio = BPF_CORE_READ(rq, bio);
  struct bvec_iter bi_iter;
  bi_iter = BPF_CORE_READ(bio, bi_iter);
  nr_bytes += bi_iter.bi_bvec_done;
  for (int i = 0; i < MAX_BIO_PER_RQ; i++) {
    if (bio == NULL) {
      break;
    }
    int bio_flag = BPF_CORE_READ(bio, bi_flags);
    bi_iter = BPF_CORE_READ(bio, bi_iter);
    if (bi_iter.bi_size <= nr_bytes) {
      if (bio_flag & BIO_TRACE_MASK) {
        bio_cnt++;
        struct event *task_info =
            bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
        if (!task_info) {
          return 0;
        }
        set_common_info(task_info, 0, 0, block_rq_complete,
                        bio_rq_association_info);
        task_info->bio_rq_association_info.dev = 0;
        task_info->bio_rq_association_info.rq = (unsigned long long)rq;
        task_info->bio_rq_association_info.bio = (unsigned long long)bio;
        bpf_ringbuf_submit(task_info, 0);
      }
    } else {
      break;
    }
    nr_bytes -= bi_iter.bi_size;
    bio = BPF_CORE_READ(bio, bi_next);
  }
  return 0;
}

SEC("raw_tp/block_rq_insert")
int raw_tracepoint__block_rq_insert(struct bpf_raw_tracepoint_args *ctx) {
  struct request *rq = (struct request *)(ctx->args[0]);
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  // bpf_get_current_comm(&task_info->comm, 80);
  set_common_info(task_info, 0, 0, block_rq_insert, rq_info);
  set_rq_comm_info(task_info, rq, 0);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("raw_tp/block_rq_issue")
int raw_tracepoint__block_rq_issue(struct bpf_raw_tracepoint_args *ctx) {
  struct request *rq = (struct request *)(ctx->args[0]);
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  // bpf_get_current_comm(&task_info->comm, 80);
  set_common_info(task_info, 0, 0, block_rq_issue, rq_info);
  set_rq_comm_info(task_info, rq, 0);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}
static inline void set_bio_rq_association_info(struct event *task_info,
                                               struct request *rq,
                                               struct bio *bio, dev_t dev) {
  task_info->bio_rq_association_info.dev = dev;
  task_info->bio_rq_association_info.rq = (unsigned long long)rq;
  task_info->bio_rq_association_info.bio = (unsigned long long)bio;
  task_info->bio_rq_association_info.request_queue =
      (unsigned long long)BPF_CORE_READ(rq, q);
}

SEC("kprobe/__rq_qos_track")
int BPF_KPROBE(trace_rq_qos_track, struct rq_qos *q, struct request *rq,
               struct bio *bio) {
  // dev_t dev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
  // if (common_filter(0, 0, dev, 0, 0)) {
  //   return 1;
  // }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  // bpf_get_current_comm(&task_info->comm, 80);
  set_common_info(task_info, 0, 0, rq_qos_track, bio_rq_association_info);
  set_bio_rq_association_info(task_info, rq, bio, 0);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("kprobe/__rq_qos_merge")
int BPF_KPROBE(trace_rq_qos_merge, struct rq_qos *q, struct request *rq,
               struct bio *bio) {
  // dev_t dev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
  // if (common_filter(0, 0, dev, 0, 0)) {
  //   return 1;
  // }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_common_info(task_info, 0, 0, rq_qos_merge, bio_rq_association_info);
  set_bio_rq_association_info(task_info, rq, bio, 0);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("kprobe/__rq_qos_done")
int BPF_KPROBE(trace_rq_qos_done, struct rq_qos *q, struct request *rq) {
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_common_info(task_info, 0, 0, rq_qos_done, rq_info);
  set_rq_comm_info(task_info, rq, 0);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

// SEC("kprobe/__rq_qos_requeue")
// int BPF_KPROBE(trace_rq_qos_requeue,struct rq_qos*q,struct request*rq){
//   u64 id = bpf_get_current_pid_tgid();
//   pid_t tgid = id >> 32;
//   pid_t tid = id & 0xffffffff;
//   struct gendisk *disk = BPF_CORE_READ(rq, rq_disk);
//   dev_t dev =
//       BPF_CORE_READ(disk, major) << 20 | BPF_CORE_READ(disk, first_minor);
//   if (common_filter(tid, tgid, dev, 0, 0)) {
//     return 1;
//   }
//   struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event),
//   0); if (!task_info) {
//     return 0;
//   }
//   bpf_get_current_comm(&task_info->comm, 80);
//   set_common_info(task_info, tid, tgid, rq_qos_requeue , rq_info);
//   set_rq_comm_info(task_info, rq, dev);
//   bpf_ringbuf_submit(task_info, 0);
//   return 0;
// }

SEC("raw_tp/block_bio_queue")
int raw_tracepoint__block_bio_queue(struct bpf_raw_tracepoint_args *ctx) {
  struct bio *bio = (struct bio *)(ctx->args[0]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  // dev_t dev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
  if (common_filter(tid, tgid, 0, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  // bpf_get_current_comm(&task_info->comm, 80);
  set_common_info(task_info, 0, 0, block_bio_queue, bio_info);
  task_info->bio_info.bio = (unsigned long long)bio;
  task_info->bio_info.dev = 0;
  task_info->bio_info.bio_info_type = queue_first_bio;
  task_info->bio_info.bio_op = BPF_CORE_READ(bio, bi_opf);
  unsigned int bvec_cnt = BPF_CORE_READ(bio, bi_vcnt);
  struct bvec_array_info *bvecs =
      bpf_ringbuf_reserve(&rb, sizeof(struct bvec_array_info), 0);
  if (bvecs == NULL) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  bvecs->info_type = bio_bvec_info;
  bvecs->bvec_cnt = bvec_cnt;
  bvecs->bio = (unsigned long long)bio;
  struct bio_vec *bv = BPF_CORE_READ(bio, bi_io_vec);
  for (int i = 0; i < (bvec_cnt & MAX_BVEC_PER_BIO); i++) {
    struct bio_vec *v = bv + i;
    struct page *p = BPF_CORE_READ(v, bv_page);
    bvecs->bvecs[i].inode = BPF_CORE_READ(p, mapping, host, i_ino);
    bvecs->bvecs[i].index = BPF_CORE_READ(p, index);
    bvecs->bvecs[i].bv_len = BPF_CORE_READ(v, bv_len);
    bvecs->bvecs[i].bv_offset = BPF_CORE_READ(v, bv_offset);
  }
  bpf_ringbuf_submit(task_info, 0);
  bpf_ringbuf_submit(bvecs, 0);
  return 0;
}

// SEC("raw_tp/block_plug") //TODO:
// int raw_tracepoint__block_plug(struct bpf_raw_tracepoint_args *ctx) {
//   struct request_queue *q = (struct request_queue *)(ctx->args[0]);
//   u64 id = bpf_get_current_pid_tgid();
//   pid_t tgid = id >> 32;
//   pid_t tid = id & 0xffffffff;
//   struct gendisk *disk = BPF_CORE_READ(q, disk);
//   dev_t dev =
//       BPF_CORE_READ(disk, major) << 20 | BPF_CORE_READ(disk, first_minor);
//   if (common_filter(tid, tgid, dev, 0, 0)) {
//     return 1;
//   }
//   struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event),
//   0);
//   if (!task_info) {
//     return 0;
//   }
//   bpf_get_current_comm(&task_info->comm, 80);
//   set_common_info(task_info, tid, tgid, block_plug, rq_plug_info);
//   task_info->rq_plug_info.dev = dev;
//   task_info->rq_plug_info.plug_or_unplug = 1;
//   task_info->rq_plug_info.request_queue = (unsigned long long)q;
//   bpf_ringbuf_submit(task_info, 0);
//   return 0;
// }

// SEC("raw_tp/block_unplug")
// int raw_tracepoint__block_unplug(struct bpf_raw_tracepoint_args *ctx) {
//   struct request_queue *q = (struct request_queue *)(ctx->args[0]);
//   unsigned int depth = (unsigned int)(ctx->args[1]);
//   bool explicit = (bool)(ctx->args[2]);
//   u64 id = bpf_get_current_pid_tgid();
//   pid_t tgid = id >> 32;
//   pid_t tid = id & 0xffffffff;
//   struct gendisk *disk = BPF_CORE_READ(q, disk);
//   dev_t dev =
//       BPF_CORE_READ(disk, major) << 20 | BPF_CORE_READ(disk, first_minor);
//   if (common_filter(tid, tgid, dev, 0, 0)) {
//     return 1;
//   }
//   struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event),
//   0); if (!task_info) {
//     return 0;
//   }
//   bpf_get_current_comm(&task_info->comm, 80);
//   set_common_info(task_info, tid, tgid, block_unplug, rq_plug_info);
//   task_info->rq_plug_info.dev = dev;
//   task_info->rq_plug_info.plug_or_unplug = 0;
//   task_info->rq_plug_info.request_queue = (unsigned long long)q;
//   bpf_ringbuf_submit(task_info, 0);
//   return 0;
// }

// TP_PROTO(struct bio *bio, unsigned int new_sector),

// SEC("raw_tp/block_split") // TODO:
// int raw_tracepoint__block_split(struct bpf_raw_tracepoint_args *ctx) {
//   struct bio *bio = (struct bio *)(ctx->args[0]);
//   // unsigned int new_sector = (unsigned int)(ctx->args[1]);
//   u64 id = bpf_get_current_pid_tgid();
//   pid_t tgid = id >> 32;
//   pid_t tid = id & 0xffffffff;
//   dev_t dev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
//   // if (common_filter(tid, tgid, dev, 0, 0)) {
//   //   return 1;
//   // }
//   struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event),
//   0); if (!task_info) {
//     return 0;
//   }
//   bpf_get_current_comm(&task_info->comm, 80);
//   set_common_info(task_info, tid, tgid, block_split, bio_info);
//   task_info->bio_info.bio = (unsigned long long)bio;
//   task_info->bio_info.dev = dev;
//   task_info->bio_info.bio_info_type = split_bio;
//   task_info->bio_info.bio_op = BPF_CORE_READ(bio, bi_opf);
//   struct bvec_iter bi_iter = BPF_CORE_READ(bio, bi_iter);
//   task_info->bio_info.bvec_idx_start = bi_iter.bi_idx;
//   struct bio *parent_bio = BPF_CORE_READ(bio, bi_private);
//   if(parent_bio == NULL){
//     bpf_ringbuf_discard(task_info, 0);
//     return 0;
//   }
//   task_info->bio_info.parent_bio = (unsigned long long)parent_bio;
//   bi_iter = BPF_CORE_READ(parent_bio, bi_iter);
//   task_info->bio_info.bvec_idx_end = bi_iter.bi_idx;
//   bpf_ringbuf_submit(task_info, 0);
//   return 0;
// }

// TP_PROTO(struct bio *bio, dev_t dev, sector_t from),
// TP_fast_assign(
// 		__entry->dev		= bio_dev(bio);
// 		__entry->sector		= bio->bi_iter.bi_sector;
// 		__entry->nr_sector	= bio_sectors(bio);
// 		__entry->old_dev	= dev;
// 		__entry->old_sector	= from;
// 		blk_fill_rwbs(__entry->rwbs, bio->bi_opf);
// 	),
// SEC("raw_tp/block_bio_remap")
// int raw_tracepoint__block_bio_remap(struct bpf_raw_tracepoint_args *ctx) {
//   struct bio *bio = (struct bio *)(ctx->args[0]);
//   dev_t old_dev = (dev_t)(ctx->args[1]);
//   sector_t from = (sector_t)(ctx->args[2]);
//   u64 id = bpf_get_current_pid_tgid();
//   pid_t tgid = id >> 32;
//   pid_t tid = id & 0xffffffff;
//   dev_t dev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
//   if (common_filter(tid, tgid, dev, 0, 0)) {
//     return 1;
//   }
//   struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event),
//   0); if (!task_info) {
//     return 0;
//   }
//   bpf_get_current_comm(&task_info->comm, 80);
//   set_comm_info(task_info, tid, tgid, block_bio_remap, bio_info);
//   set_bio_info(task_info, bio, dev);
//   task_info->bio_layer_info.old_dev = old_dev;
//   task_info->bio_layer_info.old_sector = from;
//   bpf_ringbuf_submit(task_info, 0);
//   return 0;
// }

// TP_PROTO(struct request *rq, dev_t dev, sector_t from),
// TP_fast_assign(
// 		__entry->dev		= disk_devt(rq->rq_disk);
// 		__entry->sector		= blk_rq_pos(rq);
// 		__entry->nr_sector	= blk_rq_sectors(rq);
// 		__entry->old_dev	= dev;
// 		__entry->old_sector	= from;
// 		__entry->nr_bios	= blk_rq_count_bios(rq);
// 		blk_fill_rwbs(__entry->rwbs, rq->cmd_flags);
// 	),
// SEC("raw_tp/block_rq_remap")
// int raw_tracepoint__block_rq_remap(struct bpf_raw_tracepoint_args* ctx){
//   struct request* rq = (struct request*)(ctx->args[0]);
//   dev_t dev = (dev_t)(ctx->args[1]);
//   sector_t from = (sector_t)(ctx->args[2]);
//   return 0;
// }
// SEC("tp/block/block_rq_remap") //TODO:
// int tracepoint__block_rq_remap(struct trace_event_raw_block_rq_remap *ctx) {
//   dev_t dev = (dev_t)(ctx->dev);
//   u64 id = bpf_get_current_pid_tgid();
//   pid_t tgid = id >> 32;
//   pid_t tid = id & 0xffffffff;
//   if (common_filter(tid, tgid, dev, 0, 0)) {
//     return 1;
//   }
//   struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event),
//   0); if (!task_info) {
//     return 0;
//   }
//   bpf_get_current_comm(&task_info->comm, 80);
//   set_comm_info(task_info, tid, tgid, block_bio_complete, block_layer);
//   task_info->bio_layer_info.dev = dev;
//   task_info->bio_layer_info.old_dev = ctx->old_dev;
//   task_info->bio_layer_info.old_sector = ctx->old_sector;
//   task_info->bio_layer_info.bio_sector = ctx->sector;
//   task_info->bio_layer_info.bio_size = ctx->nr_sector;
//   task_info->bio_layer_info.nr_bios = ctx->nr_bios;
//   bpf_probe_read_str(&task_info->bio_layer_info.rwbs,
//                      sizeof(task_info->bio_layer_info.rwbs), ctx->rwbs);
//   bpf_ringbuf_submit(task_info, 0);
//   return 0;
// }
