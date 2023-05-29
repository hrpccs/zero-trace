#pragma once

#include "hook_point.h"
#define MAX_COMM_LEN 80
#define MAX_BIO_PER_RQ 32
#define MAX_BVEC_PER_BIO 32

struct event {
  long long timestamp;
  int pid;
  int tid;
  enum kernel_hook_type event_type;
  enum info_type info_type;
  char comm[MAX_COMM_LEN];
  union {
    struct {
      unsigned long bio_sector;
      unsigned int bio_size;
      // enum block_layer_act action;
      unsigned long dev;
      // 0 to 20 bit of cmd_flags is valid, check blktrace_api.h to get
      // corresponding string check kernel/trace/blktrace.c
      unsigned int cmd_flags;
      union {
        unsigned int new_sector;
        unsigned int nr_rq;
        struct {
          unsigned long old_dev;
          unsigned int old_sector;
          int hasRWBS;
          unsigned int nr_bios;
          char rwbs[8];
        };
      };
    } bio_layer_info;
    struct {
      unsigned long dev;
      unsigned long long inode;
      unsigned long long dir_inode;
      unsigned long file_offset;
      unsigned long file_bytes;
    } vfs_layer_info;
    struct {
      unsigned long long bio;
      unsigned long dev;
      unsigned int bvec_cnt;
      struct bvec {
        unsigned long long inode;
        unsigned long long bv_len;
        unsigned long long bv_offset;
      } bvecs[MAX_BVEC_PER_BIO];
    } bio_info;
    struct {
      unsigned long dev;
      unsigned long relative_bio_cnt;
      unsigned long long bios[MAX_BIO_PER_RQ];
    } rq_info;
  };
  // for validation
};