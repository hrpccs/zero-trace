#pragma once

#include "hook_point.h"
#define MAX_COMM_LEN 80
#define MAX_BIO_PER_RQ 31
#define MAX_BVEC_PER_BIO 255
#define MAXLEN_VMA_NAME 64
#define MAX_LEVEL 10

struct bvec {
  unsigned long long inode;
  unsigned long long index;
  unsigned long long bv_len;
  unsigned long long bv_offset;
};
struct bvec_array_info {
  unsigned long long bio;
  enum info_type info_type;
  struct bvec bvecs[MAX_BVEC_PER_BIO];
  unsigned int bvec_cnt;
};

struct abs_path {
  char name[MAX_LEVEL][MAXLEN_VMA_NAME+1];	//abslote object file path
};

enum bio_info_type {
  queue_first_bio,
  split_bio,
  comm_bio,
};

struct event {
  long long timestamp;
  int pid;
  int tid;
  enum kernel_hook_type event_type;
  enum info_type info_type;
  char comm[MAX_COMM_LEN];
  union {
    struct {
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
      unsigned long bio_op;
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
      unsigned long long request_queue;
    } bio_rq_association_info; // 对于 bio 和 request 关联的事件，add, remove,
                               // merge
    struct {
      unsigned long dev;
      unsigned long long request_queue;
      unsigned short plug_or_unplug;
    } rq_plug_info; // 对于 request 的 plug 和 unplug 事件
  };
};