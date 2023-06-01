#pragma once

#include "hook_point.h"
#define MAX_COMM_LEN 80
#define MAX_BIO_PER_RQ 31
#define MAX_BVEC_PER_BIO 255

struct bvec {
  unsigned long long inode;
  unsigned long long bv_len;
  unsigned long long bv_offset;
};
struct bvecArray {
  struct bvec bvecs[MAX_BVEC_PER_BIO];
  unsigned int bvec_cnt;
};

enum bio_info_type {
  queue_bio,
  split_bio,
  comm_bio,
};

struct event {
  long long timestamp;
  enum kernel_hook_type event_type;
  enum info_type info_type;
  char comm[MAX_COMM_LEN];
  union {
    struct {
      int pid;
      int tid;
      unsigned long dev;
      unsigned long long inode;
      unsigned long long dir_inode;
      unsigned long file_offset;
      unsigned long file_bytes;
    } vfs_layer_info;
    struct {
      unsigned long long bio;
      unsigned long long parent_bio;
      enum bio_info_type bio_info_type;
      unsigned long dev;
      unsigned short bvec_idx_start;
      unsigned short bvec_idx_end;
    } bio_info; // 对于 bio 的 split，queue，end 事件。
    struct {
      unsigned long dev;
      unsigned long long rq;
      unsigned long long request_queue; 
    } rq_info; // 对于单一 request 的事件，如创建、释放
    struct {
      unsigned long dev;
      unsigned long long bio;
      unsigned long long rq;
    } bio_rq_association_info; // 对于 bio 和 request 关联的事件，add, remove,
                               // merge
    struct {
      unsigned long dev;
      unsigned long long rq;
      unsigned long long plug;
      unsigned short plug_or_unplug;
    } rq_plug_info; // 对于 request 的 plug 和 unplug 事件
  };
};