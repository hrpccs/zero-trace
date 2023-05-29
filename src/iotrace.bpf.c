#include "vmlinux.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "event_defs.h"
#include "filter.h"
#include "hook_point.h"
#include "system_macro.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} rb SEC(".maps");

unsigned int target_tgid = 0;                   // pid
unsigned int target_tid = 0;                    // tid
unsigned long long target_file_inode = 0;       // file inode
unsigned long long target_direrctory_inode = 0; // directory inode
unsigned long target_dev = 0;                   // device
char task_name[40] = {0};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

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

  if (target_direrctory_inode != 0) {
    if (dir_inode != target_direrctory_inode) {
      return 1;
    }
  }

  if (target_file_inode != 0) {
    if (inode != target_file_inode) {
      return 1;
    }
  }

  return 0;
}

static inline int task_comm_filter(char *comm) {
  for (int i = 0; i < MAX_COMM_LEN; i++) {
    if (comm[i] == '\0') {
      break;
    }
    if (comm[i] != task_name[i]) {
      return 1;
    }
  }
  return 0;
}

static inline void set_comm_info(struct event *task_info, pid_t tgid, pid_t tid,
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

SEC("fentry/vfs_read")
// int BPF_PROG(enter_vfs_read, struct file* file, char *buf, size_t count,
// loff_t *pos){
int BPF_PROG(enter_vfs_read) {
  struct file *file = NULL;
  size_t count = 0;
  loff_t *pos = NULL;
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
  if (common_filter(tid, tgid, dev, i_ino, i_inop)) {
    return 0;
  }

  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tgid, tid, vfs_read_enter, vfs_layer);
  loff_t offset = 0;
  bpf_probe_read(&offset, sizeof(loff_t), pos);
  set_fs_info(task_info, i_ino, i_inop, dev, offset, count);
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
  if (common_filter(tid, tgid, dev, i_ino, i_inop)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }

  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tgid, tid, vfs_read_exit, vfs_layer);
  loff_t offset = 0;
  if (pos != NULL) {
    bpf_probe_read(&offset, sizeof(loff_t), pos);
    if ((long long)offset - ret >= 0) {
      offset -= ret;
    }
  }
  bpf_probe_read(&offset, sizeof(loff_t), pos);
  set_fs_info(task_info, i_ino, i_inop, dev, offset, count);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fentry/vfs_write")
int BPF_PROG(enter_vfs_write) {
  struct file *file = NULL;
  size_t count = 0;
  loff_t *pos = NULL;
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
  if (common_filter(tid, tgid, dev, i_ino, i_inop)) {
    return 0;
  }

  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }

  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tgid, tid, vfs_write_enter, vfs_layer);
  loff_t offset = 0;
  bpf_probe_read(&offset, sizeof(loff_t), pos);
  set_fs_info(task_info, i_ino, i_inop, dev, offset, count);
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
  if (common_filter(tid, tgid, dev, i_ino, i_inop)) {
    return 0;
  }

  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }

  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tgid, tid, vfs_write_exit, vfs_layer);
  loff_t offset = 0;
  if (pos != NULL) {
    bpf_probe_read(&offset, sizeof(loff_t), pos);
    if ((long long)offset - ret >= 0) {
      offset -= ret;
    }
  }
  bpf_probe_read(&offset, sizeof(loff_t), pos);
  set_fs_info(task_info, i_ino, i_inop, dev, offset, count);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

// block layer raw tracepoints
// /sys/kernel/debug/tracing/events/block/*
// ctx->args 是 trace_proto 中的参数
// TP_PROTO 从 linux kernel 代码中 include/trace/events/block.h 中找到

// TP_PROTO(struct buffer_head *bh),
// TP_fast_assign(
// 		__entry->dev		= bh->b_bdev->bd_dev;
// 		__entry->sector		= bh->b_blocknr;
// 		__entry->size		= bh->b_size;
// 	),
SEC("raw_tp/block_touch_buffer") // TODO:
int raw_tracepoint__block_buffer_touch(struct bpf_raw_tracepoint_args *ctx) {
  struct buffer_head *bh = (struct buffer_head *)(ctx->args[0]);
  // bh->b_assoc_map->host->i_ino  buffer 关联 page 所属 file 的 inode
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  struct inode *inode = BPF_CORE_READ(bh, b_assoc_map, host);
  ino_t i_ino = BPF_CORE_READ(inode, i_ino);
  dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev); // FIXME:
  if (common_filter(tid, tgid, dev, i_ino, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }

  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tgid, tid, block_touch_buffer, block_layer);
  task_info->bio_layer_info.dev = dev;
  task_info->bio_layer_info.bio_sector = BPF_CORE_READ(bh, b_blocknr);
  task_info->bio_layer_info.bio_size = BPF_CORE_READ(bh, b_size);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("raw_tp/block_dirty_buffer") // TODO:
int raw_tracepoint__block_buffer_dirty(struct bpf_raw_tracepoint_args *ctx) {
  struct buffer_head *bh = (struct buffer_head *)(ctx->args[0]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  struct inode *inode = BPF_CORE_READ(bh, b_assoc_map, host);
  ino_t i_ino = BPF_CORE_READ(inode, i_ino);
  dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
  if (common_filter(tid, tgid, dev, i_ino, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }

  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tgid, tid, block_dirty_buffer, block_layer);
  task_info->bio_layer_info.dev = dev;
  task_info->bio_layer_info.bio_sector = BPF_CORE_READ(bh, b_blocknr);
  task_info->bio_layer_info.bio_size = BPF_CORE_READ(bh, b_size);
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

static inline void set_rq_info(struct event *task_info, struct request *rq,
                               dev_t dev, unsigned int *nr_bytes) {
  // task_info->bio_layer_info.dev = dev;
  // unsigned int rq_cmd_flags = BPF_CORE_READ(rq, cmd_flags);
  // task_info->bio_layer_info.cmd_flags = rq_cmd_flags;
  // sector_t sector = BPF_CORE_READ(rq, __sector);
  // if(rq_is_passthrough(rq_cmd_flags) || sector == (sector_t)-1){
  //   task_info->bio_layer_info.bio_sector = 0;
  // }else{
  //   task_info->bio_layer_info.bio_sector = sector;
  // }
  // if(nr_bytes != NULL){
  //   task_info->bio_layer_info.bio_size = *nr_bytes >> SECTOR_SHIFT;
  // }else{
  //   if(rq_is_passthrough(rq_cmd_flags)){
  //     task_info->bio_layer_info.bio_size = 0;
  //   }else{
  //     task_info->bio_layer_info.bio_size = BPF_CORE_READ(rq, __data_len) >>
  //     9;
  //   }
  // }

  task_info->rq_info.dev = dev;
  int bio_cnt = 0;
  struct bio *bio = BPF_CORE_READ(rq, bio);
  for (int j = 0; j < MAX_BIO_PER_RQ; j++) {
    if (bio == NULL) {
      break;
    }
    bio_cnt++;
    task_info->rq_info.bios[j] = (u64)bio;
    bio = BPF_CORE_READ(bio, bi_next);
  }
  task_info->rq_info.relative_bio_cnt = bio_cnt;
}

static inline void set_bio_info(struct event *task_info, struct bio *bio,
                                dev_t dev) {
  // task_info->bio_layer_info.dev = dev;
  // task_info->bio_layer_info.cmd_flags = BPF_CORE_READ(bio, bi_opf);
  // struct bvec_iter bi_iter = BPF_CORE_READ(bio, bi_iter);
  // task_info->bio_layer_info.bio_sector = bi_iter.bi_sector;
  // task_info->bio_layer_info.bio_size = bi_iter.bi_size >> 9;
  task_info->bio_info.bvec_cnt = BPF_CORE_READ(bio, bi_vcnt);
  task_info->bio_info.bio = (u64)bio;
  task_info->bio_info.dev = dev;
  struct bio_vec *bv = BPF_CORE_READ(bio, bi_io_vec);
  for (int i = 0; i < (task_info->bio_info.bvec_cnt & (MAX_BVEC_PER_BIO - 1));
       i++) {
    struct bio_vec *v = bv + i;
    struct page *page = BPF_CORE_READ(v, bv_page);
    // ino_t inode = page->mapping->host->i_ino;
    ino_t inode = BPF_CORE_READ(page, mapping, host, i_ino);
    int index = BPF_CORE_READ(page, index);
    task_info->bio_info.bvecs[i].inode = inode;
    task_info->bio_info.bvecs[i].bv_len = BPF_CORE_READ(v, bv_len);
    task_info->bio_info.bvecs[i].bv_offset =
        (index << 12) + BPF_CORE_READ(v, bv_offset);
  }
}

// TP_PROTO(struct request *rq),
// TP_fast_assign(
// 	__entry->dev	   = rq->rq_disk ? disk_devt(rq->rq_disk) : 0;
// 	__entry->sector    = blk_rq_trace_sector(rq);
// 	__entry->nr_sector = blk_rq_trace_nr_sectors(rq);
// 	blk_fill_rwbs(__entry->rwbs, rq->cmd_flags);
// 	__get_str(cmd)[0] = '\0';
// ),
SEC("raw_tp/block_rq_requeue")
int raw_tracepoint__block_rq_requeue(struct bpf_raw_tracepoint_args *ctx) {
  struct request *rq = (struct request *)(ctx->args[0]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  struct gendisk *disk = BPF_CORE_READ(rq, rq_disk);
  dev_t dev =
      BPF_CORE_READ(disk, major) << 20 | BPF_CORE_READ(disk, first_minor);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }

  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tgid, tid, block_rq_requeue, block_layer);
  set_rq_info(task_info, rq, dev, NULL);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

// TP_PROTO(struct request *rq, int error, unsigned int nr_bytes),
// TP_fast_assign(
// 	__entry->dev	   = rq->rq_disk ? disk_devt(rq->rq_disk) : 0;
// 	__entry->sector    = blk_rq_pos(rq);
// 	__entry->nr_sector = nr_bytes >> 9;
// 	__entry->error     = error;

// 	blk_fill_rwbs(__entry->rwbs, rq->cmd_flags);
// 	__get_str(cmd)[0] = '\0';
// ),
SEC("raw_tp/block_rq_complete")
int raw_tracepoint__block_rq_complete(struct bpf_raw_tracepoint_args *ctx) {
  struct request *rq = (struct request *)(ctx->args[0]);
  int error = (int)(ctx->args[1]);
  unsigned int nr_bytes = (unsigned int)(ctx->args[2]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  struct gendisk *disk = BPF_CORE_READ(rq, rq_disk);
  dev_t dev =
      BPF_CORE_READ(disk, major) << 20 | BPF_CORE_READ(disk, first_minor);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, block_rq_complete, rq_info);
  set_rq_info(task_info, rq, dev, &nr_bytes);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

// TP_PROTO(struct request *rq),
// TP_fast_assign(
// 	__entry->dev	   = rq->rq_disk ? disk_devt(rq->rq_disk) : 0;
// 	__entry->sector    = blk_rq_trace_sector(rq);
// 	__entry->nr_sector = blk_rq_trace_nr_sectors(rq);
// 	__entry->bytes     = blk_rq_bytes(rq);

// 	blk_fill_rwbs(__entry->rwbs, rq->cmd_flags);
// 	__get_str(cmd)[0] = '\0';
// 	memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
// ),
SEC("raw_tp/block_rq_insert")
int raw_tracepoint__block_rq_insert(struct bpf_raw_tracepoint_args *ctx) {
  struct request *rq = (struct request *)(ctx->args[0]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  struct gendisk *disk = BPF_CORE_READ(rq, rq_disk);
  dev_t dev =
      BPF_CORE_READ(disk, major) << 20 | BPF_CORE_READ(disk, first_minor);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, block_rq_insert, block_layer);
  set_rq_info(task_info, rq, dev, NULL);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("raw_tp/block_rq_issue")
int raw_tracepoint__block_rq_issue(struct bpf_raw_tracepoint_args *ctx) {
  struct request *rq = (struct request *)(ctx->args[0]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  struct gendisk *disk = BPF_CORE_READ(rq, rq_disk);
  dev_t dev =
      BPF_CORE_READ(disk, major) << 20 | BPF_CORE_READ(disk, first_minor);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, block_rq_issue, block_layer);
  set_rq_info(task_info, rq, dev, NULL);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("raw_tp/block_rq_merge")
int raw_tracepoint__block_rq_merge(struct bpf_raw_tracepoint_args *ctx) {
  struct request *rq = (struct request *)(ctx->args[0]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  struct gendisk *disk = BPF_CORE_READ(rq, rq_disk);
  dev_t dev =
      BPF_CORE_READ(disk, major) << 20 | BPF_CORE_READ(disk, first_minor);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, block_rq_merge, block_layer);
  set_rq_info(task_info, rq, dev, NULL);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

// TP_PROTO(struct request_queue *q, struct bio *bio),
// TP_fast_assign(
// 	__entry->dev		= bio_dev(bio);
// 	__entry->sector		= bio->bi_iter.bi_sector;
// 	__entry->nr_sector	= bio_sectors(bio);
// 	__entry->error		= blk_status_to_errno(bio->bi_status);
// 	blk_fill_rwbs(__entry->rwbs, bio->bi_opf);
// ),
SEC("raw_tp/block_bio_complete")
int raw_tracepoint__block_bio_complete(struct bpf_raw_tracepoint_args *ctx) {
  struct request_queue *q = (struct request_queue *)(ctx->args[0]);
  struct bio *bio = (struct bio *)(ctx->args[1]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  dev_t dev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, block_bio_complete, block_layer);
  set_bio_info(task_info, bio, dev);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

// TP_PROTO(struct bio *bio)
// TP_fast_assign(
// 		__entry->dev		= bio_dev(bio);
// 		__entry->sector		= bio->bi_iter.bi_sector;
// 		__entry->nr_sector	= bio_sectors(bio);
// 		blk_fill_rwbs(__entry->rwbs, bio->bi_opf);
// 		memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
// 	),
SEC("raw_tp/block_bio_bounce")
int raw_tracepoint__block_bio_bounce(struct bpf_raw_tracepoint_args *ctx) {
  struct bio *bio = (struct bio *)(ctx->args[0]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  dev_t dev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, block_bio_complete, block_layer);
  set_bio_info(task_info, bio, dev);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("raw_tp/block_bio_backmerge")
int raw_tracepoint__block_bio_backmerge(struct bpf_raw_tracepoint_args *ctx) {
  struct bio *bio = (struct bio *)(ctx->args[0]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  dev_t dev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, block_bio_complete, block_layer);
  set_bio_info(task_info, bio, dev);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("raw_tp/block_bio_frontmerge")
int raw_tracepoint__block_bio_frontmerge(struct bpf_raw_tracepoint_args *ctx) {
  struct bio *bio = (struct bio *)(ctx->args[0]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  dev_t dev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, block_bio_complete, block_layer);
  set_bio_info(task_info, bio, dev);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("raw_tp/block_bio_queue")
int raw_tracepoint__block_bio_queue(struct bpf_raw_tracepoint_args *ctx) {
  struct bio *bio = (struct bio *)(ctx->args[0]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  dev_t dev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, block_bio_complete, block_layer);
  set_bio_info(task_info, bio, dev);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("raw_tp/block_getrq")
int raw_tracepoint__block_getrq(struct bpf_raw_tracepoint_args *ctx) {
  struct bio *bio = (struct bio *)(ctx->args[0]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  dev_t dev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, block_bio_complete, block_layer);
  set_bio_info(task_info, bio, dev);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

// TP_PROTO(struct request_queue *q)
// TP_fast_assign(
// 		memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
// 	)
SEC("raw_tp/block_plug")
int raw_tracepoint__block_plug(struct bpf_raw_tracepoint_args *ctx) {
  struct request_queue *q = (struct request_queue *)(ctx->args[0]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  struct gendisk *disk = BPF_CORE_READ(q, disk);
  dev_t dev =
      BPF_CORE_READ(disk, major) << 20 | BPF_CORE_READ(disk, first_minor);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, block_bio_complete, block_layer);
  // no other info
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

// TP_PROTO(struct request_queue *q, unsigned int depth, bool explicit),
// TP_fast_assign(
// 		__entry->nr_rq = depth;
// 		memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
// 	),
SEC("raw_tp/block_unplug")
int raw_tracepoint__block_unplug(struct bpf_raw_tracepoint_args *ctx) {
  struct request_queue *q = (struct request_queue *)(ctx->args[0]);
  unsigned int depth = (unsigned int)(ctx->args[1]);
  bool explicit = (bool)(ctx->args[2]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  struct gendisk *disk = BPF_CORE_READ(q, disk);
  dev_t dev =
      BPF_CORE_READ(disk, major) << 20 | BPF_CORE_READ(disk, first_minor);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, block_bio_complete, block_layer);
  // no other info FIXME: convay depth
  task_info->bio_layer_info.nr_rq = depth;
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

// TP_PROTO(struct bio *bio, unsigned int new_sector),
// TP_fast_assign(
// 	__entry->dev		= bio_dev(bio);
// 	__entry->sector		= bio->bi_iter.bi_sector;
// 	__entry->new_sector	= new_sector;
// 	blk_fill_rwbs(__entry->rwbs, bio->bi_opf);
// 	memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
// ),
SEC("raw_tp/block_split")
int raw_tracepoint__block_split(struct bpf_raw_tracepoint_args *ctx) {
  struct bio *bio = (struct bio *)(ctx->args[0]);
  unsigned int new_sector = (unsigned int)(ctx->args[1]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  dev_t dev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, block_bio_complete, block_layer);
  set_bio_info(task_info, bio, dev);
  task_info->bio_layer_info.new_sector = new_sector;
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

// TP_PROTO(struct bio *bio, dev_t dev, sector_t from),
// TP_fast_assign(
// 		__entry->dev		= bio_dev(bio);
// 		__entry->sector		= bio->bi_iter.bi_sector;
// 		__entry->nr_sector	= bio_sectors(bio);
// 		__entry->old_dev	= dev;
// 		__entry->old_sector	= from;
// 		blk_fill_rwbs(__entry->rwbs, bio->bi_opf);
// 	),
SEC("raw_tp/block_bio_remap")
int raw_tracepoint__block_bio_remap(struct bpf_raw_tracepoint_args *ctx) {
  struct bio *bio = (struct bio *)(ctx->args[0]);
  dev_t old_dev = (dev_t)(ctx->args[1]);
  sector_t from = (sector_t)(ctx->args[2]);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  dev_t dev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, block_bio_complete, block_layer);
  set_bio_info(task_info, bio, dev);
  task_info->bio_layer_info.old_dev = old_dev;
  task_info->bio_layer_info.old_sector = from;
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

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
SEC("tp/block/block_rq_remap")
int tracepoint__block_rq_remap(struct trace_event_raw_block_rq_remap *ctx) {
  dev_t dev = (dev_t)(ctx->dev);
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 1;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, block_bio_complete, block_layer);
  task_info->bio_layer_info.dev = dev;
  task_info->bio_layer_info.old_dev = ctx->old_dev;
  task_info->bio_layer_info.old_sector = ctx->old_sector;
  task_info->bio_layer_info.bio_sector = ctx->sector;
  task_info->bio_layer_info.bio_size = ctx->nr_sector;
  task_info->bio_layer_info.nr_bios = ctx->nr_bios;
  bpf_probe_read_str(&task_info->bio_layer_info.rwbs,
                     sizeof(task_info->bio_layer_info.rwbs), ctx->rwbs);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fentry/submit_bio")
int BPF_PROG(trace__submit_bio,
             struct bio *bio) { // ctx->args[0] 是 ptgreg 的指向原触发
                                // tracepoint 的函数的参数， ctx->args[1] 是
                                // tracepoint 定义 trace 函数的第一个参数
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  dev_t dev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, submit_bio, bio_info);
  set_bio_info(task_info, bio, dev);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fentry/bio_endio")
int BPF_PROG(trace__bio_endio, struct bio *bio) {
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  dev_t dev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, bio_endio, bio_info);
  set_bio_info(task_info, bio, dev);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}

SEC("fentry/submit_bio_noacct")
int BPF_PROG(trace__submit_bio_1,
             struct bio *bio) { // ctx->args[0] 是 ptgreg 的指向原触发
                                // tracepoint 的函数的参数， ctx->args[1] 是
                                // tracepoint 定义 trace 函数的第一个参数
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t tid = id & 0xffffffff;
  dev_t dev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
  if (common_filter(tid, tgid, dev, 0, 0)) {
    return 0;
  }
  struct event *task_info = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (!task_info) {
    return 0;
  }
  bpf_get_current_comm(&task_info->comm, 80);
  set_comm_info(task_info, tid, tgid, submit_bio, bio_info);
  set_bio_info(task_info, bio, dev);
  bpf_ringbuf_submit(task_info, 0);
  return 0;
}