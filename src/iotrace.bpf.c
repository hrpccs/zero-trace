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
} rb SEC(".maps");

struct filter_config filter_config = {
    .tgid = 0,
    .tid = 0,
    .inode = 0,
    .directory_inode = 0,
    .dev = 0,
    .command_len = 0,
    .filter_by_command = 0,
    .cgroup_id = 0,
};

short qemu_enable = 1;    // 必需加上至少进程级的过滤
short syscall_enable = 1; // 必需加上至少进程级的过滤
short vfs_enable = 1;     // 必需加上至少进程级的过滤
short block_enable = 1;
short scsi_enable = 1;
short nvme_enable = 1;
short ext4_enable = 1;
short filemap_enable = 1;
short iomap_enable = 1;
short sched_enable = 0;
short virtio_enable = 1;


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

static int inline pid_filter(pid_t tgid, pid_t tid) {
  // assert(filter_config.tgid != 0 || filter_config.tid != 0); !
  if (filter_config.tgid != tgid) {
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
  *inode = BPF_CORE_READ(iinode, i_ino);
  if (filter_config.inode != 0 && filter_config.inode != *inode) {
    return 1;
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
  int *fd_ref = bpf_map_lookup_elem(&fd_ref_map, &fd);
  int ret = 0;
  ino_t inode = 0;
  dev_t dev = 0;
  ino_t dir_inode = 0;
  if (fd_ref == NULL) {
    if (filter_config.dev != 0 || filter_config.inode != 0 ||
        filter_config.directory_inode != 0) {
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
    struct inode *iinode = BPF_CORE_READ(file, f_inode);
    // filter and update filterd fd map
    ret = filter_inode_dev_dir(iinode, file, &inode, &dev, &dir_inode);
    if (ret) {
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
  if (inodep != NULL)
    *inodep = inode;
  if (devp != NULL)
    *devp = dev;
  if (dir_inodep != NULL)
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
  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, NULL, NULL, NULL);
  if (ret) {
    return 0;
  }
  // TODO:
  struct event * e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (e) {
    bpf_debug("submit event iotrace\n");
    e->event_type = vfs_write_enter;
    e->info_type = vfs_layer;
    bpf_ringbuf_submit(e, 0);
  }

  bpf_debug("syscall read enter: fd %d buf %lx count %lu\n", fd, buf, count);
  return 0;
}
SEC("kretsyscall/read")
int BPF_KPROBE_SYSCALL(read_ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  bpf_debug("syscall read exit\n");
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
  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, NULL, NULL, NULL);
  if (ret) {
    return 0;
  }
  bpf_debug("syscall write enter: fd %d buf %lx count %lu\n", fd, buf, count);
  return 0;
}
SEC("kretsyscall/write")
int BPF_KPROBE_SYSCALL(write_ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  bpf_debug("syscall write exit\n");
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

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, NULL, NULL, NULL);
  if (ret) {
    return 0;
  }

  bpf_debug("syscall pread64 enter: fd %d count %lu offset %lu\n", fd, count, offset);
  return 0;
}
SEC("kretsyscall/pread64")
int BPF_KPROBE_SYSCALL(pread64_ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

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

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, NULL, NULL, NULL);
  if (ret) {
    return 0;
  }

  bpf_debug("syscall pwrite64 enter: fd %d count %lu offset %lu\n", fd, count, offset);
  return 0;
}
SEC("kretsyscall/pwrite64")
int BPF_KPROBE_SYSCALL(pwrite64_ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  bpf_debug("syscall pwrite64 exit\n");
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

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, NULL, NULL, NULL);
  if (ret) {
    return 0;
  }
  bpf_debug("syscall readv enter: fd %d vec %lx vlen %lu\n", fd, vec, vlen);
  return 0;
}
SEC("kretsyscall/readv")
int BPF_KPROBE_SYSCALL(readv_ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  bpf_debug("syscall readv exit\n");
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

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, NULL, NULL, NULL);
  if (ret) {
    return 0;
  }
  bpf_debug("syscall writev enter: fd %d vec %lx vlen %lu\n", fd, vec, vlen);
  return 0;
}
SEC("kretsyscall/writev")
int BPF_KPROBE_SYSCALL(writev_ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  bpf_debug("syscall writev exit\n");
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

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, NULL, NULL, NULL);
  if (ret) {
    return 0;
  }
  bpf_debug("syscall preadv enter: fd %d vec %lx vlen %lu\n", fd, vec, vlen);
  return 0;
}
SEC("kretsyscall/preadv")
int BPF_KPROBE_SYSCALL(preadv_ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
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

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, NULL, NULL, NULL);
  if (ret) {
    return 0;
  }
  bpf_debug("syscall pwritev enter: fd %d vec %lx vlen %lu\n", fd, vec, vlen);
  return 0;
}
SEC("kretsyscall/pwritev")
int BPF_KPROBE_SYSCALL(pwritev_ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
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

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, NULL, NULL, NULL);
  if (ret) {
    return 0;
  }
  bpf_debug("syscall fsync enter: fd %d\n", fd);
  return 0;
}
SEC("kretsyscall/fsync")
int BPF_KPROBE_SYSCALL(fsync_ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
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

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, NULL, NULL, NULL);
  if (ret) {
    return 0;
  }
  bpf_debug("syscall fdatasync enter: fd %d\n", fd);
  return 0;
}
SEC("kretsyscall/fdatasync")
int BPF_KPROBE_SYSCALL(fdatasync_ret) {
  if (!syscall_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

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
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

  int ret = update_fd_inode_map_and_filter_dev_inode_dir(fd, NULL, NULL, NULL);
  if (ret) {
    return 0;
  }
  bpf_debug("syscall sync_file_range enter: fd %d offset %lu nbytes %lu \n", fd,
             offset, nbytes);
  return 0;
}
SEC("kretsyscall/sync_file_range")
int BPF_KPROBE_SYSCALL(sync_file_range_ret) {
  if (!syscall_enable) {
    return 0;
  }

  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }

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
  if (vfs_filter_inode(ino)) {
    return 0;
  }
  unsigned long nr_bytes = iter->count;
  loff_t *pos = NULL;
  loff_t offset = 0;
  bpf_core_read(&pos, sizeof(pos), ctx + 2);
  bpf_core_read(&offset, sizeof(offset), pos);

  bpf_printk("do_iter_read enter:	ino %lu offset %lu len %lu\n", ino,
  offset, nr_bytes);
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
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
    return 0;
  }

  bpf_printk("do_iter_read exit:	ino %lu\n", ino);
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
  if (vfs_filter_inode(ino)) {
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
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
    return 0;
  }
  // bpf_printk("do_iter_write exit:	ino %lu\n", ino);
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
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
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
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
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
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
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
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
    return 0;
  }
  bpf_printk("vfs_iocb_iter_read exit:	ino %lu\n", ino);
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
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
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
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
    return 0;
  }
  bpf_printk("vfs_read exit:	ino %lu\n", ino);
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
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
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
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
    return 0;
  }
  bpf_printk("vfs_write exit:	ino %lu\n", ino);
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
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
    return 0;
  }

  bpf_printk("vfs_fsync_range enter:	ino %lu start %lu end %lu\n", ino, start,
             end);
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
  struct file *file = iocb->ki_filp;
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
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
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  struct file *file = iocb->ki_filp;
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
    return 0;
  }
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
  struct file *file = iocb->ki_filp;
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
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
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  struct file *file = iocb->ki_filp;
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
    return 0;
  }
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
  struct file *file = iocb->ki_filp;
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
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
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  struct file *file = iocb->ki_filp;
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
    return 0;
  }
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
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
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
  if (!vfs_enable) {
    return 0;
  }
  pid_t tgid, tid;
  if (get_and_filter_pid(&tgid, &tid)) {
    return 0;
  }
  struct file *file = iocb->ki_filp;
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
    return 0;
  }

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
  struct file *file = iocb->ki_filp;
  ino_t ino = file->f_inode->i_ino;
  if (vfs_filter_inode(ino)) {
    return 0;
  }
  return 0;
}

SEC("tp_btf/sched_switch")
int handle_tp_sched_1(struct bpf_raw_tracepoint_args *ctx) {
  if (!sched_enable) {
    return 0;
  }
  struct task_struct *prev = (struct task_struct *)(ctx->args[0]);
  struct task_struct *next = (struct task_struct *)(ctx->args[1]);
  pid_t prev_pid = BPF_CORE_READ(prev, pid);
  pid_t next_pid = BPF_CORE_READ(next, pid);
  pid_t prev_tgid = BPF_CORE_READ(prev, tgid);
  pid_t next_tgid = BPF_CORE_READ(next, tgid);
  // filter , at least one of them is in the filter
  if (filter_config.tgid != 0 &&
      (filter_config.tgid != prev_tgid && filter_config.tgid != next_tgid)) {
    return 0;
  }

  if (filter_config.tid != 0 &&
      (filter_config.tid != prev_pid && filter_config.tid != next_pid)) {
    return 0;
  }

  bpf_printk("sched_switch target prev_pid: %d next_pid: %d\n", prev_pid,
             next_pid);
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

long long active_bio_cnt = 0;
long long active_rq_cnt = 0;

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

SEC("tp_btf/block_bio_queue") // 开始追踪一个 bio
int handle_tp7(struct bpf_raw_tracepoint_args *ctx)
{
  if(!block_enable){
    return 0;
  }
	struct bio *bio = (struct bio *)(ctx->args[0]);
	struct bio_vec *first_bv = bio->bi_io_vec;
	struct page *first_page = first_bv->bv_page;
	struct inode *inode = first_page->mapping->host;
	ino_t i_ino = inode->i_ino;
  // check if inode is in the ino_ref_map
  // if not, return
  int *ino_ref = bpf_map_lookup_elem(&inode_ref_map, &i_ino);
  if (ino_ref == NULL) {
    return 0;
  } else {
    // bpf_debug("ino_ref_map: %d\n", *ino_ref);
    bpf_debug("block_bio_queue target i_ino: %ld\n", i_ino);
  }

  // add to bio_ref_map
  int *bio_ref = bpf_map_lookup_elem(&bio_ref_map, &bio);
  if (bio_ref == NULL) {
    int a = 0;
    bpf_map_update_elem(&bio_ref_map, &bio, &a, BPF_ANY);
    bpf_debug("block_bio_queue bio curr active_bio_cnt: %lld\n", __sync_fetch_and_add(&active_bio_cnt, 1));
  } else {
    bpf_debug("block_bio_queue bio %lx already in bio_ref_map\n", bio);
  }
   // 近似的计算 bio 对应文件逻辑地址的大致范围（认为 bio 的 bi_vec 是顺序递增的）
  // 用于和 vfs 的请求进行匹配

	sector_t sector = bio->bi_iter.bi_sector;
	size_t nr_sector = bio->bi_iter.bi_size >> 9;
	int last_index = (bio->bi_vcnt - 1) & (512 - 1);
	struct bio_vec last_bv;
	bpf_core_read(&last_bv, sizeof(struct bio_vec), first_bv + last_index);
	int last_page_index = BPF_CORE_READ(last_bv.bv_page, index);
	// struct bio_vec *last_bv = &bio->bi_io_vec[last_index];
	loff_t start_offset = (first_page->index << 12) + first_bv->bv_offset;
	loff_t end_offset = (last_page_index << 12) + last_bv.bv_offset + last_bv.bv_len;
	bpf_printk("block_bio_queue target  bio: %lx sector: %ld nr_sector: %ld\n", bio, sector,
		   nr_sector);
	bpf_printk("                       i_ino: %ld start_offset: %ld end_offset: %ld\n", i_ino,
		   start_offset, end_offset);
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
  } else {
    bpf_debug("bio_ref_map: %d\n", *bio_ref);
  }

	sector_t sector = bio->bi_iter.bi_sector;
	size_t nr_sector = bio->bi_iter.bi_size >> 9;
	bpf_printk("block_bio_bounce target bio: %lx sector: %ld nr_sector: %ld\n", bio, sector,
		   nr_sector);
	return 0;
}


SEC("fentry/__rq_qos_track")
int BPF_PROG(trace_rq_qos_track, struct rq_qos *q, struct request *rq, struct bio *bio)
{
  if(!block_enable){
    return 0;
  }
  // check bio_ref_map
  // if exsits,  add rq to request_ref_map
  int *bio_ref = bpf_map_lookup_elem(&bio_ref_map, &bio);
  if (bio_ref == NULL) {
    return 0;
  } else {
  }
  // add to request_ref_map
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    int a = 0;
    bpf_map_update_elem(&request_ref_map, &rq, &a, BPF_ANY);
    bpf_debug("rq_qos_track bio: %lx rq:%lx\n", bio,rq);
    bpf_debug("curr active_rq_cnt: %lld\n", __sync_fetch_and_add(&active_rq_cnt, 1));
  } else {
    bpf_debug("rq_qos_track:request %lx already in request_ref_map\n",rq);
  }
	// bpf_printk("rq_qos_track target bio: %lx rq: %lx\n", bio, rq);
	return 0;
}

SEC("fentry/__rq_qos_merge") // 代替 block_bio_merge, 用来建立 bio 和 request 的关系
int BPF_PROG(trace_rq_qos_merge, struct rq_qos *q, struct request *rq, struct bio *bio)
{
  if(!block_enable){
    return 0;
  }
  // check bio_ref_map
  // if exsits,  add rq to request_ref_map
  int *bio_ref = bpf_map_lookup_elem(&bio_ref_map, &bio);
  if (bio_ref == NULL) {
    return 0;
  } else {
  }
  // add to request_ref_map
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    int a = 0;
    bpf_map_update_elem(&request_ref_map, &rq, &a, BPF_ANY);
    bpf_debug("rq_qos_merge bio: %lx rq: %lx\n", bio,rq);
    bpf_debug("curr active_rq_cnt: %lld\n", __sync_fetch_and_add(&active_rq_cnt, 1));
  } else {
    bpf_debug("rq_qos_merge:request %lx already in request_ref_map\n", rq);
  }
	// bpf_printk("rq_qos_merge target bio: %lx rq: %lx\n", bio, rq);
	return 0;
}

// SEC("tp_btf/block_bio_backmerge")
// int handle_tp8(struct bpf_raw_tracepoint_args *ctx)
// {
// 	struct bio *bio = (struct bio *)(ctx->args[0]);
// 	sector_t sector = bio->bi_iter.bi_sector;
// 	size_t nr_sector = bio->bi_iter.bi_size >> 9;
// 	bpf_printk("block_bio_backmerge target bio: %lx sector: %ld nr_sector: %ld\n", bio, sector,
// 		   nr_sector);
// 	return 0;
// }

// SEC("tp_btf/block_bio_frontmerge")
// int handle_tp9(struct bpf_raw_tracepoint_args *ctx)
// {
// 	struct bio *bio = (struct bio *)(ctx->args[0]);
// 	sector_t sector = bio->bi_iter.bi_sector;
// 	size_t nr_sector = bio->bi_iter.bi_size >> 9;
// 	bpf_printk("block_bio_frontmerge target bio: %lx sector: %ld nr_sector: %ld\n", bio, sector,
// 		   nr_sector);
// 	return 0;
// }
SEC("fentry/__rq_qos_done_bio") // 代替 block_bio_complete, 用来删除 bio 的引用
int BPF_PROG(trace_rq_qos_done_bio, struct rq_qos *q, struct bio *bio)
{
  if(!block_enable){
    return 0;
  }
  // if bio is in bio_ref_map, delete it
  int *bio_ref = bpf_map_lookup_elem(&bio_ref_map, &bio);
  if (bio_ref == NULL) {
    return 0;
  } else {
    bpf_map_delete_elem(&bio_ref_map, &bio);
    // active_bio_cnt--;
    bpf_debug("curr active_bio_cnt: %lld\n", __sync_fetch_and_add(&active_bio_cnt, -1));
	  bpf_printk("rq_qos_done_bio target bio: %lx\n", bio);
  }

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
	return 0;
}

// SEC("tp_btf/block_bio_complete")
// int handle_tp10(struct bpf_raw_tracepoint_args *ctx)
// {
// 	struct bio *bio = (struct bio *)(ctx->args[1]);
// 	sector_t sector = bio->bi_iter.bi_sector;
// 	size_t nr_sector = bio->bi_iter.bi_size >> 9;
// 	bpf_printk("block_bio_complete target bio: %lx sector: %ld nr_sector: %ld\n", bio, sector,
// 		   nr_sector);
// 	return 0;
// }

SEC("tp_btf/block_rq_insert")
int handle_tp4(struct bpf_raw_tracepoint_args *ctx)
{ 
  if(!block_enable){
    return 0;
  }
  // check if request is in request_ref_map
  // if not, return
	struct request *rq = (struct request *)(ctx->args[0]);
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  } else {
    // bpf_debug("request_ref_map: %d\n", *request_ref);
  }
	long nr_sector = rq->__data_len;
	sector_t sector = rq->__sector;
	bpf_printk(" rq_insert target rq: %lx start: %lx len: %lx\n", rq, sector, nr_sector);
	return 0;
}

// SEC("tp_btf/block_rq_issue")
// int handle_tp(struct bpf_raw_tracepoint_args *ctx)
// { // ctx->args[0] 是 ptgreg 的指向原触发 tracepoint 的函数的参数， ctx->args[1] 是 tracepoint 定义 trace 函数的第一个参数
//   if(!block_enable){
//     return 0;
//   }
//   // check if request is in request_ref_map
//   // if not, return
// 	struct request *rq = (struct request *)(ctx->args[0]);
//   int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
//   if (request_ref == NULL) {
//     return 0;
//   } else {
//     bpf_debug("request_ref_map: %d\n", *request_ref);
//   }
// 	long nr_sector = rq->__data_len;
// 	sector_t sector = rq->__sector;
// 	bpf_printk(" rq_issue target rq: %lx start: %ld len: %ld\n", rq, sector, nr_sector);
// 	return 0;
// }

// SEC("tp_btf/block_rq_complete")
// int handle_tp2(struct bpf_raw_tracepoint_args *ctx)
// {
// 	struct request *rq = (struct request *)(ctx->args[0]);
// 	// dev_t dev = rq->part->bd_dev;
// 	// tracepoint 里面是 __entry->dev	   = rq->rq_disk ? disk_devt(rq->rq_disk) : 0;
// 	sector_t sector = rq->__sector;
// 	long nr_sector = rq->__data_len;
// 	bpf_printk(" rq_complete target rq: %lx start: %ld len: %ld\n", rq, sector, nr_sector);
// 	return 0;
// }



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
    // active_rq_cnt--;
    bpf_debug("rq_qos_done: curr active_rq_cnt: %lld\n", __sync_fetch_and_add(&active_rq_cnt, -1));
  }

	bpf_printk("rq_qos_done target rq: %lx\n", rq);
	return 0;
}



//rq_qos_issue
SEC("fentry/__rq_qos_issue")
int BPF_PROG(trace_rq_qos_issue, struct rq_qos *q, struct request *rq)
{
  if(!block_enable){
    return 0;
  }
  // check if request is in request_ref_map
  // if not, return
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  } else {
	  bpf_printk("rq_qos_issue target  rq: %lx\n", rq);
  }

	return 0;
}

//rq_qos_requeue
SEC("fentry/__rq_qos_requeue")
int BPF_PROG(trace_rq_qos_requeue, struct rq_qos *q, struct request *rq)
{
  if(!block_enable){
    return 0;
  }
  // check if request is in request_ref_map
  // if not, return
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  } else {
	bpf_printk("rq_qos_requeue target  rq: %lx\n", rq);
  }
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
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  } else {
  }
	struct nvme_command *cmd = (struct nvme_command *)(ctx->args[1]);


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
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  } else {
  }
	bpf_printk("nvme_complete_rq rq: %llx\n", rq);
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
  int *request_ref = bpf_map_lookup_elem(&request_ref_map, &rq);
  if (request_ref == NULL) {
    return 0;
  } else {
  }
	bpf_printk("nvme_sq rq: %llx\n", rq);
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
  } else {
  }

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
  } else {
  }
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
	loff_t offset = rq->__sector << 9;
	unsigned long nr_bytes = rq->__data_len << 9;
  dev_t dev = rq->rq_disk->major << 20 | rq->rq_disk->first_minor;
	bpf_printk("virtio_queue_rq target rq: %lx offset %lx bytes %lx\n", rq, offset, nr_bytes);
	return 0;
}

/* virtio-pci */


// #include <qemu/osdep.h>
// #include "hw/virtio/virtio-blk.h"
// #include "block/thread-pool.h"

// /* qemu user space */
// #define QEMU_EXE "/home/hrpccs/workspace/qemu-proj/qemu/build/x86_64-softmmu/qemu-system-x86_64"
// #define UPROBE_QEMU_HOOK(hook_point_name) "uprobe/" QEMU_EXE ":"  hook_point_name


// //virtio_blk_handle_request
// SEC(UPROBE_QEMU_HOOK("virtio_blk_handle_request"))
// int BPF_KPROBE(uprobe_virtio_blk_handle_request, VirtIOBlockReq *req, MultiReqBuffer *mrb)
// { 
// 	bpf_printk("virtio_blk_handle_request %lx %lx\n", req, mrb);
// 	// VirtIODevice* vdev = (VirtIODevice*)BPF_CORE_READ_USER(req,dev);
// 	VirtIOBlock *vblk;
// 	VirtIODevice *vdev;
// 	VirtQueue *vq;
// 	int queue_index = 0;
// 	long long offset = 0;
// 	bpf_probe_read_user(&vq, sizeof(VirtQueue *), &(req->vq));
// 	// long long nr_bytes = 0;
// 	bpf_probe_read_user(&offset, sizeof(long long), &(req->sector_num));
// 	// bpf_probe_read_user(&nr_bytes,sizeof(long long),&(req->qiov.size));
// 	bpf_probe_read_user(&vblk, sizeof(VirtIOBlock *), &(req->dev));
// 	vdev = &(vblk->parent_obj);
// 	int device_id = 0;
// 	bpf_probe_read_user(&device_id, sizeof(int), &(vdev->device_id));
// 	bpf_printk("dev_id: %lx, queue_index: %lx,offset: %llx\n", device_id,queue_index, offset << 9);
// 	return 0;
// }
//virtio_blk_req_complete
// SEC(UPROBE_QEMU_HOOK(virtio_blk_req_complete))


