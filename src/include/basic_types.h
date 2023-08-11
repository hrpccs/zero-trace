#pragma once

#include "event_defs.h"
#include "hook_point.h"
#include <iostream>
#include <memory>
#include <memory_resource>
#include <set>
#include <string>
#include <utility>
#include <vector>
#include <chrono>
#include <ctime>

class Event {
public:
  Event(struct event* e) {
    timestamp = e->timestamp;
    event_type = e->event_type;
    info_type = e->info_type;
    trigger_type = e->trigger_type;
  }
  Event(Event& e) {
    timestamp = e.timestamp;
    event_type = e.event_type;
    info_type = e.info_type;
    trigger_type = e.trigger_type;
  }
  Event(Event&& e) {
    timestamp = e.timestamp;
    event_type = e.event_type;
    info_type = e.info_type;
    trigger_type = e.trigger_type;
  }
  ~Event() {}
  long long timestamp;
  enum kernel_hook_type event_type;
  enum info_type info_type;
  enum trigger_type trigger_type;
};

class Request {
  // a request is consisted of a series of syncronous events and several
  // asyncronous objects a request is identified by the first event a request is
  // ended by the last event
public:
  static unsigned long long request_id;
  Request() { 
    id = this->request_id++; 
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    start_tm = *std::localtime(&now_time);
  }
  virtual ~Request() {}
  virtual void addEvent(std::unique_ptr<Event> event) {
    events.push_back(std::move(event));
  }
  void setSyscallInfo(struct event* e){
    syscall_pid = e->syscall_layer_info.tgid;
    syscall_tid = e->syscall_layer_info.tid;
    syscall_dev = e->syscall_layer_info.dev;
    syscall_inode = e->syscall_layer_info.inode;
    syscall_dir_inode = e->syscall_layer_info.dir_inode;
    syscall_fd = e->syscall_layer_info.fd;
  }

  void setRet(int ret){
    this->syscall_ret = ret;
  }

  void setSyscallRange(unsigned long offset,unsigned int bytes){
    this->syscall_offset = offset;
    this->syscall_bytes = bytes;
  }

  void setQemuInfo(struct event* e){
    isQemuRq = true;
    qemu_tid = e->qemu_layer_info.tid;
    virtblk_guest_offset = e->qemu_layer_info.offset;
    virtblk_nr_bytes = e->qemu_layer_info.nr_bytes;
  }

  void setVirtioRange(unsigned long sector,unsigned int nr_bytes){
    this->isVirtIO = true;
    this->driver_rq_offset = sector<<9;
    this->driver_rq_nr_bytes = nr_bytes;
  }

  unsigned long long id;
  std::vector<std::unique_ptr<Event>> events;
  int syscall_tid,syscall_pid;
  int syscall_fd;
  unsigned long syscall_dev,syscall_inode,syscall_dir_inode;
  int syscall_ret;
  unsigned long syscall_offset;
  unsigned int syscall_bytes;
  bool isVirtIO = false;
  unsigned long driver_rq_offset;
  unsigned long driver_rq_nr_bytes;

  // just for qemu 
  bool isQemuRq = false;
  int qemu_tid;
  // to match guest's dirver_rq_offset
  unsigned long virtblk_guest_offset;
  unsigned int virtblk_nr_bytes;
  unsigned long host_syscall_offset;
  unsigned int host_syscall_nr_bytes;

  // for statistics
  struct BioStatistic {
    bool done = false;
    bool bio_is_throttled = false;
    bool bio_is_bounce = false;
    unsigned long long bio_queue_time = 0;
    unsigned long long bio_schedule_start_time = 0; // rq_insert
    unsigned long long bio_schedule_end_time = 0; // rq_issue
    unsigned long long bio_complete_time = 0;
  };

  unsigned long long start_time;
  unsigned long long end_time;
  std::vector<BioStatistic> bio_statistics;

  // store real time
  std::tm start_tm;
};
