#pragma once
#include "event_defs.h"
#include "hook_point.h"
#include <cassert>
#include <cereal/archives/binary.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/vector.hpp>
#include <chrono>
#include <ctime>
#include <iostream>
#include <list>
#include <memory>
#include <memory_resource>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

class Event {
public:
  Event() {}
  Event(struct event *e) {
    timestamp = e->timestamp;
    event_type = e->event_type;
    info_type = e->info_type;
    trigger_type = e->trigger_type;
  }
  Event(Event &e) {
    timestamp = e.timestamp;
    event_type = e.event_type;
    info_type = e.info_type;
    trigger_type = e.trigger_type;
  }
  Event(Event &&e) {
    timestamp = e.timestamp;
    event_type = e.event_type;
    info_type = e.info_type;
    trigger_type = e.trigger_type;
  }
  ~Event() {}

  // 重载 new 运算符
  void *operator new(std::size_t size) {
    if (size != sizeof(Event)) {
      throw std::bad_alloc();
    }

    // 从内存池中获取内存块
    void *ptr = nullptr;
    while (ptr == nullptr) {
      ptr = memory_pool_.allocate();
      if (ptr == nullptr) {
        std::cout << "memory pool is empty, waiting..." << std::endl;
      }
    }

    return ptr;
  }

  // 重载 delete 运算符
  void operator delete(void *ptr) noexcept {
    // 将内存块返回给内存池
    memory_pool_.deallocate(ptr);
  }

  long long timestamp;
  enum kernel_hook_type event_type;
  enum info_type info_type;
  enum trigger_type trigger_type;
  template <class Archive> void serialize(Archive &archive) {
    archive(timestamp, event_type, info_type, trigger_type);
  }

  class MemoryPool {
  public:
    MemoryPool() {
      // 分配内存池
      pool_ = static_cast<char *>(std::malloc(kPoolSize * sizeof(Event)));
      if (pool_ == nullptr) {
        throw std::bad_alloc();
      }

      // 初始化内存池
      for (std::size_t i = 0; i < kPoolSize; i += sizeof(Event)) {
        free_list_.push_back(pool_ + i);
      }
    }

    ~MemoryPool() {
      // 释放内存池
      std::free(pool_);
    }

    // 从内存池中获取内存块
    void *allocate() {
      std::lock_guard<std::mutex> lock(mutex_);
      void *ptr = nullptr;
      if (!free_list_.empty()) {
        ptr = free_list_.front();
        free_list_.pop_front();
      } else {
        // 当前内存池已经耗尽，从备用内存池中申请一块内存
        std::lock_guard<std::mutex> lock2(mutex2_);
        if (!backup_free_list_.empty()) {
          ptr = backup_free_list_.front();
          backup_free_list_.pop_front();
          // 将备用内存池中的内存加入到当前内存池中
          free_list_.push_back(ptr);
        } else {
          // 备用内存池也已经耗尽，申请一块新的内存
          expand_pool();
          ptr = free_list_.front();
          free_list_.pop_front();
        }
      }
      return ptr;
    }

    // 将内存块返回给内存池
    void deallocate(void *ptr) noexcept {
      // printf("deallocate\n");
      std::lock_guard<std::mutex> lock(mutex_);
      free_list_.push_front(ptr);
    }

  private:
    // 内存池的大小
    static constexpr std::size_t kPoolSize = (1 << 14);

    // 内存池
    char *pool_;

    // 空闲内存块列表
    std::mutex mutex_;
    std::list<void *> free_list_;

    // 备用内存池
    std::mutex mutex2_;
    std::list<void *> backup_free_list_;

    // 动态扩展内存池
    void expand_pool() {
      char *new_pool =
          static_cast<char *>(std::malloc(kPoolSize * sizeof(Event)));
      if (new_pool == nullptr) {
        throw std::bad_alloc();
      }
      // 将新申请的内存分割成 Event 大小的内存块，并加入到当前内存池中
      for (std::size_t i = 0; i < kPoolSize * sizeof(Event);
           i += sizeof(Event)) {
        free_list_.push_back(new_pool + i);
      }
      // 将新申请的内存块加入到备用内存池中
      backup_free_list_.push_back(new_pool);
    }
  };

  // 内存池
  static MemoryPool memory_pool_;
};
class Request {
  // a request is consisted of a series of syncronous events and several
  // asyncronous objects a request is identified by the first event a request is
  // ended by the last event
public:
  Request() {
    id = this->request_id++;
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    // start_tm = *std::localtime(&now_time);
  }
  virtual ~Request() {}
  virtual void addEvent(std::unique_ptr<Event> event) {
    events.push_back(std::move(event));
  }
  void setSyscallInfo(struct event *e) {
    syscall_pid = e->syscall_layer_info.tgid;
    syscall_tid = e->syscall_layer_info.tid;
    syscall_dev = e->syscall_layer_info.dev;
    syscall_inode = e->syscall_layer_info.inode;
    syscall_dir_inode = e->syscall_layer_info.dir_inode;
    syscall_fd = e->syscall_layer_info.fd;
  }

  void setHostSyscallInfo(struct event *e) {
    host_syscall_dev = e->syscall_layer_info.dev;
    host_syscall_inode = e->syscall_layer_info.inode;
    host_syscall_dir_inode = e->syscall_layer_info.dir_inode;
  }

  void setHostSyscallRange(unsigned long offset, unsigned int bytes) {
    this->host_syscall_offset = offset;
    this->host_syscall_nr_bytes = bytes;
  }

  void setRet(int ret) { this->syscall_ret = ret; }

  void setSyscallRange(unsigned long offset, unsigned int bytes) {
    this->syscall_offset = offset;
    this->syscall_bytes = bytes;
  }

  void setQemuInfo(struct event *e) {
    if (e->event_type == qemu__qcow2_co_pwritev_part) {
      isQemuRq = true;
      qemu_tid = e->qemu_layer_info.tid;
      virtblk_guest_offset = e->qemu_layer_info.offset;
      virtblk_nr_bytes = e->qemu_layer_info.nr_bytes;
    } else if (e->event_type == qemu__qcow2_co_preadv_part) {
      isQemuRq = true;
      qemu_tid = e->qemu_layer_info.tid;
      virtblk_guest_offset = e->qemu_layer_info.offset;
      virtblk_nr_bytes = e->qemu_layer_info.nr_bytes;
    } else if (e->event_type == qemu__qcow2_co_flush_to_os) {
      isQemuRq = true;
      qemu_tid = e->qemu_layer_info.tid;
      virtblk_guest_offset = e->qemu_layer_info.offset;
      virtblk_nr_bytes = e->qemu_layer_info.nr_bytes;
    } else if (e->event_type == qemu__raw_co_prw) {
      host_syscall_nr_bytes = e->qemu_layer_info.nr_bytes;
      host_syscall_offset = e->qemu_layer_info.offset;
    } else if (e->event_type == qemu__raw_co_flush_to_disk) {
    }

    // virtblk_nr_bytes = e->qemu_layer_info.nr_bytes;
  }

  // for statistics
  struct IOStatistic {
    IOStatistic() {}
    bool bio_is_throttled = false;
    bool bio_is_bounce = false;
    unsigned long long bio_queue_time = 0;          // bio_queue
    unsigned long long bio_schedule_start_time = 0; // rq_insert
    unsigned long long bio_schedule_end_time = 0;   // rq_issue
    unsigned long long bio_done_time = 0;           // bio_done
    unsigned long long offset = 0;
    unsigned int nr_bytes = 0;
    bool isVirtIO = false;
    int issue_idx_in_request = -1;
    int done_idx_in_request = -1;
    template <class Archive> void serialize(Archive &archive) {
      archive(bio_is_throttled, bio_is_bounce, bio_queue_time,
              bio_schedule_start_time, bio_schedule_end_time, bio_done_time,
              offset, nr_bytes, isVirtIO, issue_idx_in_request,
              done_idx_in_request);
    }
  };

  static unsigned long long request_id;
  static double estimated_q2c;
  static double estimated_q2d;
  static double estimated_d2c;
  unsigned long long id;
  std::vector<std::unique_ptr<Event>> events;
  int syscall_tid;
  int syscall_pid;
  int syscall_fd;
  unsigned long syscall_dev;
  unsigned long syscall_inode;
  unsigned long  syscall_dir_inode;
  enum rq_type syscall_rq_type;
  int syscall_ret;
  unsigned long syscall_offset; // use in top level syscall
  unsigned int syscall_bytes;   // use in top level syscall
  bool isVirtIO = false;
  bool isQemuRq = false;
  int qemu_tid;
  enum rq_type qemu_rq_type;
  unsigned long virtblk_guest_offset;
  unsigned int virtblk_nr_bytes;
  unsigned long host_syscall_offset;  // for subsyscall within qemu io
  unsigned int host_syscall_nr_bytes; // for subsyscall within qemu io
  unsigned long host_syscall_dev, host_syscall_inode, host_syscall_dir_inode;
  unsigned long long start_time;
  unsigned long long end_time;
  std::vector<IOStatistic> io_statistics;
  long long real_start_time;
  long long guest_offset_time;

  template <class Archive> void serialize(Archive &archive) {
    archive(id, events, syscall_tid, syscall_pid, syscall_fd, syscall_dev,
            syscall_inode, syscall_dir_inode, syscall_rq_type, syscall_ret,
            syscall_offset, syscall_bytes, isVirtIO, isQemuRq, qemu_tid,
            qemu_rq_type, virtblk_guest_offset, virtblk_nr_bytes,
            host_syscall_offset, host_syscall_nr_bytes, start_time, end_time,
            io_statistics, real_start_time, guest_offset_time,
            host_syscall_inode, host_syscall_dir_inode, host_syscall_dev);
  }
};
