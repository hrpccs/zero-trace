#include "vmlinux.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "event_defs.h"
#include "hook_point.h"
#include "system_macro.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define BIO_TRACE_MASK (1 << BIO_TRACE_COMPLETION)
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} rb SEC(".maps");

// hash map for abs path of each inode
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1 << 20);
  __type(key, ino_t);
  __type(value,int);
} ino_path_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct abs_path);
    //   .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    // .key_size = sizeof(u32),
    // .value_size = PATH_MAX,
    // .max_entries = 1,
} tmp_abs_path SEC(".maps");


// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

unsigned int target_tgid = 0;                   // pid
unsigned int target_tid = 0;                    // tid
unsigned long long target_file_inode = 0;       // file inode
unsigned long long target_direrctory_inode = 0; // directory inode
unsigned long target_dev = 0;                   // device
char command[MAX_COMM_LEN] = {0};
unsigned int command_len = 0;

// return 1, means will be filtered
// return 0, means will be traced
// trace pid = 0 and target pid
// trace target device
static inline int common_filter(pid_t tid, pid_t tgid, dev_t dev, ino_t inode,
                                ino_t dir_inode) {
  if (target_tgid != 0) {
    if (tgid != 0 && tgid != target_tgid) {
      return 1;
    }
  }

  if (target_tid != 0) {
    if (tid != 0 && tid != target_tid) {
      return 1;
    }
  }

  if (target_dev != 0) {
    if (dev != target_dev) {
      return 1;
    }
  }

  // if (target_direrctory_inode != 0) {
  //   if (dir_inode != target_direrctory_inode) {
  //     return 1;
  //   }
  // }

  // if (target_file_inode != 0) {
  //   if (inode != target_file_inode) {
  //     return 1;
  //   }
  // }

  return 0;
}

static inline int task_comm_filter(char *comm) {
  if(command_len == 0){
    return 0;
  }
  for (int i = 0; i < MAX_COMM_LEN; i++) {
    if (comm[i] == '\0') {
      break;
    }
    if (comm[i] != command[i]) {
      return 1;
    }
  }
  return 0;
}

static inline void set_common_info(struct event *task_info, pid_t tgid, pid_t tid,
                                 enum kernel_hook_type event_type,
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

static inline struct mount *get_real_mount(struct vfsmount *vfsmount)
{
	void *mnt = (void *)vfsmount;
	return (struct mount *)(mnt - (unsigned long)(&((struct mount *)0)->mnt));
}

static inline int read_and_store_abs_path(struct path *p, ino_t *inode,
                                          struct block_device* s_bdev) {
        struct dentry *dentry = p->dentry;
        struct dentry *parent = NULL;
        struct qstr dname = BPF_CORE_READ(dentry, d_name);
        struct vfsmount *vfsmnt = p->mnt;
        struct mount *mnt = NULL;
        // read abs path of share lib , inspired by d_path() kernel function
        // MAXLEN_VMA_NAME = 2^n;
        u32 key = 0;
        // struct abs_path *tp = bpf_map_lookup_elem(&tmp_abs_path, &key);
        struct abs_path *tp = bpf_ringbuf_reserve(&rb, sizeof(*tp), 0);
        if (tp == NULL) {
    return 1;
        }
		struct gendisk* disk = BPF_CORE_READ(s_bdev,bd_disk);
		tp->has_root = 0;
        for (int k = MAX_LEVEL - 1, idx = k; k >= 0; k--) {
    bpf_probe_read_kernel_str(&tp->name[idx][0],
                              (dname.len + 5) & (MAXLEN_VMA_NAME - 1),
                              dname.name); // weak ptr offset
    if (tp->name[idx][0] == '/') {         // is root
      mnt = get_real_mount(vfsmnt);
      struct mount *parent_mnt = BPF_CORE_READ(mnt, mnt_parent);
      tp->name[idx][0] = '\0';
      if (parent_mnt == mnt) {
        break;
      }
	  tp->has_root = 1;
      vfsmnt = &(parent_mnt->mnt);
      parent = BPF_CORE_READ(parent_mnt, mnt_mountpoint);
    } else {
      parent = BPF_CORE_READ(dentry, d_parent);
      if (parent == dentry) {
        break;
      }
      idx--;
    }
    dentry = parent;
    dname = BPF_CORE_READ(dentry, d_name);
        }
    bpf_probe_read_kernel_str(&tp->disk_name[0], 40, BPF_CORE_READ(disk, disk_name));
	tp->partno = BPF_CORE_READ(s_bdev, bd_partno);
  tp->inode = *inode;
  int a = 1;
        bpf_map_update_elem(&ino_path_map, inode, &a, BPF_ANY);
        bpf_ringbuf_submit(tp, 0);
        return 0;
}

SEC("fentry/vfs_read")
// int BPF_PROG(enter_vfs_read, struct file* file, char *buf, size_t count,
// loff_t *pos){
int BPF_PROG(enter_vfs_read) {
  struct file *file = NULL;
  size_t count = 0;
  loff_t *pos = NULL;
  bpf_probe_read(&file, sizeof(struct file *), ctx + 0);
  if(BPF_CORE_READ(file,f_op,read_iter) == NULL){
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
  if (common_filter(tid, tgid, dev, i_ino, 0)) {
    return 0;
  }

  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_filter(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  if(bpf_map_lookup_elem(&ino_path_map, &i_ino) == NULL){
    if(!read_and_store_abs_path(&p,&i_ino,BPF_CORE_READ(inode,i_sb,s_bdev))){
      goto go_on;
    }
  }
go_on:;
  set_common_info(task_info, tgid, tid, vfs_read_enter, vfs_layer);
  loff_t offset = 0;
  bpf_probe_read(&offset, sizeof(loff_t), pos);
  set_fs_info(task_info, i_ino, 0, dev, offset, count);
  bpf_ringbuf_submit(task_info, 0);
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
  if (task_comm_filter(task_info->comm)) {
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
int BPF_PROG(enter_filemap_get_pages,struct kiocb *iocb, struct iov_iter *iter,
		struct pagevec *pvec){
  struct file *file = BPF_CORE_READ(iocb, ki_filp);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  struct path p = BPF_CORE_READ(file, f_path);
  ino_t i_inop = BPF_CORE_READ(p.dentry, d_parent, d_inode, i_ino);
  ino_t i_ino = BPF_CORE_READ(inode, i_ino);
  dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
  if (common_filter(tid, tgid, 0, i_ino,0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_filter(task_info->comm)) {
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
int BPF_PROG(exit_filemap_get_pages,struct kiocb *iocb, struct iov_iter *iter,
		struct pagevec *pvec){
  struct file *file = BPF_CORE_READ(iocb, ki_filp);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  struct path p = BPF_CORE_READ(file, f_path);
  ino_t i_inop = BPF_CORE_READ(p.dentry, d_parent, d_inode, i_ino);
  ino_t i_ino = BPF_CORE_READ(inode, i_ino);
  dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
  if (common_filter(tid, tgid, 0, i_ino,0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, MAX_COMM_LEN);
  if (task_comm_filter(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, filemap_get_pages_exit, vfs_layer);
  loff_t offset = BPF_CORE_READ(iocb, ki_pos);
  unsigned long count = BPF_CORE_READ(iter, count);
  set_fs_info(task_info, i_ino,0, 0, offset, count);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fentry/mark_page_accessed")
int BPF_PROG(trace_mark_page_accessed,struct page *page){
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
  if (task_comm_filter(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, mark_page_accessed, vfs_layer);
  loff_t alloffset = (BPF_CORE_READ(page,index) <<12);
  set_fs_info(task_info, i_ino, 0, 0, alloffset,4096);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
 }
SEC("fentry/filemap_write_and_wait_range")
int BPF_PROG(trace_enter_filemap_write_and_wait_range,struct address_space *mapping,
				   loff_t start_byte, loff_t end_byte){
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
  if (task_comm_filter(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, filemap_write_and_wait_range_enter, vfs_layer);
  set_fs_info(task_info, i_ino, 0, 0, start_byte,end_byte+1-start_byte);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}


SEC("fexit/filemap_write_and_wait_range")
int BPF_PROG(trace_exit_filemap_write_and_wait_range,struct address_space *mapping,
				   loff_t start_byte, loff_t end_byte){
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
  if (task_comm_filter(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, filemap_write_and_wait_range_exit, vfs_layer);
  set_fs_info(task_info, i_ino, 0, 0, start_byte,end_byte+1-start_byte);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fentry/filemap_range_needs_writeback")
int BPF_PROG(trace_enter_filemap_range_needs_writeback,struct address_space *mapping,
				   loff_t start_byte, loff_t end_byte){
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
  if (task_comm_filter(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, filemap_range_needs_writeback_enter, vfs_layer);
  set_fs_info(task_info, i_ino, 0, 0, start_byte,end_byte+1-start_byte);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}


SEC("fexit/filemap_range_needs_writeback")
int BPF_PROG(trace_exit_filemap_range_needs_writeback,struct address_space *mapping,
				   loff_t start_byte, loff_t end_byte){
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
  if (task_comm_filter(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, filemap_range_needs_writeback_exit, vfs_layer);
  set_fs_info(task_info, i_ino, 0, 0, start_byte,end_byte+1-start_byte);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fentry/iomap_dio_rw")
int BPF_PROG(trace_enter_iomap_dio_rw,struct kiocb *iocb, struct iov_iter *iter){
  struct file *file = BPF_CORE_READ(iocb, ki_filp);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tid = id & 0xffffffff;
  pid_t tgid = id >> 32;
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  struct path p = BPF_CORE_READ(file, f_path); ino_t i_inop = BPF_CORE_READ(p.dentry, d_parent, d_inode, i_ino);
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
  if (task_comm_filter(task_info->comm)) {
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
int BPF_PROG(trace_exit_iomap_dio_rw,struct kiocb *iocb, struct iov_iter *iter){
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
  if (task_comm_filter(task_info->comm)) {
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
int BPF_PROG(trace_enter___cond_resched){
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
  if (task_comm_filter(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  set_common_info(task_info, tgid, tid, __cond_resched_enter, vfs_layer);
  set_fs_info(task_info, 0, 0, 0, 0, 0);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fexit/__cond_resched")
int BPF_PROG(trace_exit___cond_resched){
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
  if (task_comm_filter(task_info->comm)) {
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
  if(BPF_CORE_READ(file,f_op,write_iter) == NULL){
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
  if (task_comm_filter(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  if(bpf_map_lookup_elem(&ino_path_map, &i_ino) == NULL){
    if(!read_and_store_abs_path(&p,&i_ino,BPF_CORE_READ(inode,i_sb,s_bdev))){
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
  if (task_comm_filter(task_info->comm)) {
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
  task_info->rq_info.request_queue = (unsigned long long)BPF_CORE_READ(rq,q);
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
        set_common_info(task_info, 0, 0, block_rq_complete, bio_rq_association_info);
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
  set_rq_comm_info(task_info, rq,0);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}
static inline void set_bio_rq_association_info(struct event* task_info, struct request* rq,struct bio* bio,dev_t dev){
  task_info->bio_rq_association_info.dev = dev;
  task_info->bio_rq_association_info.rq = (unsigned long long)rq;
  task_info->bio_rq_association_info.bio = (unsigned long long)bio;
  task_info->bio_rq_association_info.request_queue = (unsigned long long)BPF_CORE_READ(rq, q);
}

SEC("kprobe/__rq_qos_track")
int BPF_KPROBE(trace_rq_qos_track,struct rq_qos*q,struct request*rq,struct bio* bio){
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
int BPF_KPROBE(trace_rq_qos_merge,struct rq_qos*q,struct request*rq,struct bio* bio){
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
int BPF_KPROBE(trace_rq_qos_done,struct rq_qos*q,struct request*rq){
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_common_info(task_info, 0, 0, rq_qos_done , rq_info);
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
//   struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
//   if (!task_info) {
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
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event),
  0); if (!task_info) {
    return 0;
  }
  // bpf_get_current_comm(&task_info->comm, 80);
  set_common_info(task_info, 0, 0, block_bio_queue,bio_info);
  task_info->bio_info.bio = (unsigned long long)bio;
  task_info->bio_info.dev = 0;
  task_info->bio_info.bio_info_type = queue_first_bio;
  task_info->bio_info.bio_op = BPF_CORE_READ(bio, bi_opf);
  unsigned int bvec_cnt = BPF_CORE_READ(bio, bi_vcnt);
  struct bvec_array_info* bvecs = bpf_ringbuf_reserve(&rb, sizeof(struct bvec_array_info), 0);
  if(bvecs == NULL){
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
    bvecs->bvecs[i].index = BPF_CORE_READ(p,index);
    bvecs->bvecs[i].bv_len = BPF_CORE_READ(v, bv_len);
    bvecs->bvecs[i].bv_offset = BPF_CORE_READ(v, bv_offset) ;
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
//   struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
//   if (!task_info) {
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
