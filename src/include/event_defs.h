#pragma once

#include "hook_point.h"
#define MAX_COMM_LEN 80
#define MAX_BIO_PER_RQ 31
#define MAX_BVEC_PER_BIO 255
#define MAXLEN_VMA_NAME 64
#define MAX_LEVEL 8

enum rq_type {
  RQ_TYPE_READ = 0,
  RQ_TYPE_WRITE = 1,
  RQ_TYPE_FLUSH = 2,
  // TODO: support blow。。
  RQ_TYPE_DISCARD = 3,
  RQ_TYPE_WRITE_SAME = 4,
  RQ_TYPE_WRITE_ZEROES = 5,
  RQ_TYPE_ZONE_APPEND = 6,
  RQ_TYPE_ZONE_RESET = 7,
  RQ_TYPE_ZONE_MAP = 8,
  RQ_TYPE_MAX = 9,
};
struct event {
  long long timestamp;
  enum kernel_hook_type event_type;
  enum info_type info_type;
  enum trigger_type trigger_type;
  union {
    struct {
      int tid;
      enum rq_type rq_type;
      long long virt_rq_addr;
      long long offset;
      int nr_bytes;
      int prev_tid;
    } qemu_layer_info;

    struct {
      int tid;
      int tgid;
      union {
        struct {
          unsigned long dev;
          unsigned long long inode;
          unsigned long long dir_inode;
          int fd;
        };
        struct {
          int ret;
        };
      };
    } syscall_layer_info;

    struct {
      int tid;
      int tgid;
      unsigned long offset;
      unsigned long bytes;
    } fs_layer_info;
    struct {
      unsigned long long bio;
      unsigned long long parent_bio;
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

struct filter_config {
  unsigned int tgid;
  unsigned int tid;
  unsigned long long inode;
  unsigned long long directory_inode;
  unsigned long dev;
  short filter_by_command;
  char command[MAX_COMM_LEN];
  unsigned int command_len;
  unsigned long long cgroup_id;
};