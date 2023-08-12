#include "iotracer.h"
#include "basic_types.h"
#include "event_defs.h"
#include "hook_point.h"
#include <cassert>
#include <cstddef>
#include <ctime>
#include <memory>
#include <utility>

void IOTracer::HandleBlockEvent(struct event *e) {
  if (e->event_type == kernel_hook_type::block__bio_queue) {
    int tid = e->block_layer_info.tid;
    int pid = e->block_layer_info.tgid;
    int bio_id = e->block_layer_info.bio_id;
    auto krq = requests[tid];
    if (krq == nullptr) {
      return;
    }
    krq->addEvent(std::unique_ptr<Event>(new Event(e)));
    krq->io_statistics.push_back(Request::IOStatistic());
    krq->io_statistics.back().bio_queue_time = e->timestamp;
    bio_requests[bio_id] = krq;
  } else if (e->event_type == kernel_hook_type::block__bio_add_to_rq) {
    int bio_id = e->block_layer_info.bio_id;
    int rq_id = e->block_layer_info.rq_id;
    auto it = bio_requests.find(bio_id);
    if (it != bio_requests.end()) {
      auto krq = it->second;
      auto event = std::unique_ptr<Event>(new Event(e));
      krq->addEvent(std::move(event));
      rq_requests[rq_id] = krq;
    }
  } else if (e->event_type == kernel_hook_type::block__bio_done) {
    int bio_id = e->block_layer_info.bio_id;
    auto it = bio_requests.find(bio_id);
    if (it != bio_requests.end()) {
      auto krq = it->second;
      auto event = std::unique_ptr<Event>(new Event(e));
      krq->addEvent(std::move(event));
      krq->io_statistics.back().bio_done_time = e->timestamp;
      krq->io_statistics.back().done_idx_in_request = krq->events.size() - 1;
      bio_requests.erase(it);
    }
  } else if (e->event_type == kernel_hook_type::block__rq_done) {
    int rq_id = e->block_layer_info.rq_id;
    auto it = rq_requests.find(rq_id);
    if (it != rq_requests.end()) {
      auto krq = it->second;
      auto event = std::unique_ptr<Event>(new Event(e));
      krq->addEvent(std::move(event));
      rq_requests.erase(it);
    }
  } else if (e->event_type == kernel_hook_type::block__bio_bounce) {
    int bio_id = e->block_layer_info.bio_id;
    auto it = bio_requests.find(bio_id);
    if (it != bio_requests.end()) {
      auto krq = it->second;
      auto event = std::unique_ptr<Event>(new Event(e));
      krq->addEvent(std::move(event));
      krq->io_statistics.back().bio_is_bounce = true;
    }
  } else if (e->event_type == kernel_hook_type::block__bio_throttle) {
    int bio_id = e->block_layer_info.bio_id;
    auto it = bio_requests.find(bio_id);
    if (it != bio_requests.end()) {
      auto krq = it->second;
      auto event = std::unique_ptr<Event>(new Event(e));
      krq->addEvent(std::move(event));
      krq->io_statistics.back().bio_is_bounce = true;
      krq->io_statistics.back().bio_is_throttled = true;
    }
  } else if (e->event_type == kernel_hook_type::block__rq_insert) {
    int rq_id = e->block_layer_info.rq_id;
    auto it = rq_requests.find(rq_id);
    if (it != rq_requests.end()) {
      auto krq = it->second;
      auto event = std::unique_ptr<Event>(new Event(e));
      krq->addEvent(std::move(event));
      krq->io_statistics.back().bio_schedule_start_time = e->timestamp;
    }
  } else if (e->event_type == kernel_hook_type::block__rq_issue) {
    int rq_id = e->block_layer_info.rq_id;
    auto it = rq_requests.find(rq_id);
    if (it != rq_requests.end()) {
      auto krq = it->second;
      auto event = std::unique_ptr<Event>(new Event(e));
      krq->addEvent(std::move(event));
      krq->io_statistics.back().bio_schedule_end_time = e->timestamp;
      krq->io_statistics.back().offset = e->block_layer_info.sector << 9;
      krq->io_statistics.back().nr_bytes = e->block_layer_info.nr_bytes;
      krq->io_statistics.back().issue_idx_in_request = krq->events.size() - 1;
    }
  } else if (e->event_type == kernel_hook_type::block__rq_requeue) {
    int rq_id = e->block_layer_info.rq_id;
    auto it = rq_requests.find(rq_id);
    if (it != rq_requests.end()) {
      auto krq = it->second;
      auto event = std::unique_ptr<Event>(new Event(e));
      krq->addEvent(std::move(event));
    }
  } else {
    assert(false);
  }
}

void IOTracer::HandleSyscallEvent(struct event *e) {
  int tid = e->syscall_layer_info.tid;
  int pid = e->syscall_layer_info.tgid;
  if (e->trigger_type == trigger_type::ENTRY) {
    std::shared_ptr<Request> krq;
    if (run_type == IOTracer::RUN_AS_HOST) {
      krq = requests[tid];
      if (krq == nullptr) {
        return;
      }
      krq->setHostSyscallInfo(e);
    } else {
      krq = std::make_shared<Request>();
      requests.insert(std::make_pair(tid, krq));
      krq->setSyscallInfo(e);
      krq->start_time = e->timestamp;
    }
    auto event = std::unique_ptr<Event>(new Event(e));
    krq->addEvent(std::move(event));
  } else if (e->trigger_type == trigger_type::EXIT) {
    int ret = e->syscall_layer_info.ret;
    auto it = requests.find(tid);
    if (it != requests.end()) {
      auto krq = it->second;
      if (krq == nullptr) {
        return;
      }
      auto event = std::unique_ptr<Event>(new Event(e));
      krq->addEvent(std::move(event));
      krq->setRet(ret);
      if (run_type != IOTracer::RUN_AS_HOST) {
        requests.erase(it);
        krq->end_time = e->timestamp;
        HandleDoneRequest(krq);
      }
    }
  } else {
    assert(false);
  }
}

void IOTracer::HandleFsEvent(struct event *e) {
  int tid = e->fs_layer_info.tid;
  int pid = e->fs_layer_info.tgid;
  auto it = requests.find(tid);
  if (it != requests.end()) {
    auto krq = it->second;
    if (krq == nullptr) {
      return;
    }
    if (e->trigger_type != trigger_type::EXIT) {
      unsigned long offset = e->fs_layer_info.offset;
      unsigned long bytes = e->fs_layer_info.bytes;
      if (run_type == IOTracer::RUN_AS_HOST) {
        krq->setHostSyscallRange(offset, bytes);
      } else {
        krq->setSyscallRange(offset, bytes);
      }
    }
    auto event = std::unique_ptr<Event>(new Event(e));
    krq->addEvent(std::move(event));
  }
}
void IOTracer::HandleSchedEvent(struct event *e) {
  if (config.sched_enable == false) {
    return;
  }
  int prev_tid = e->sched_layer_info.prev_tid;
  int next_tid = e->sched_layer_info.next_tid;

  auto it = requests.find(prev_tid);
  if (it != requests.end()) {
    auto krq = it->second;
    if (krq == nullptr) {
      return;
    }
    auto event = std::unique_ptr<Event>(new Event(e));
    event->trigger_type = trigger_type::ENTRY;
    krq->addEvent(std::move(event));
  }

  it = requests.find(next_tid);
  if (it != requests.end()) {
    auto krq = it->second;
    if (krq == nullptr) {
      return;
    }
    auto event = std::unique_ptr<Event>(new Event(e));
    event->trigger_type = trigger_type::EXIT;
    krq->addEvent(std::move(event));
  }
}
void IOTracer::HandleScsiEvent(struct event *e) {
  if (config.scsi_enable == false) {
    return;
  }
  int rq_id = e->scsi_layer_info.rq_id;
  auto it = rq_requests.find(rq_id);
  if (it != rq_requests.end()) {
    auto krq = it->second;
    if (krq == nullptr) {
      return;
    }
    auto event = std::unique_ptr<Event>(new Event(e));
    krq->addEvent(std::move(event));
  }
}
void IOTracer::HandleNvmeEvent(struct event *e) {
  if (config.nvme_enable == false) {
    return;
  }
  int rq_id = e->nvme_layer_info.rq_id;
  auto it = rq_requests.find(rq_id);
  if (it != rq_requests.end()) {
    auto krq = it->second;
    if (krq == nullptr) {
      return;
    }
    auto event = std::unique_ptr<Event>(new Event(e));
    krq->addEvent(std::move(event));
  }
}
void IOTracer::HandleVirtioEvent(struct event *e) {
  if (config.virtio_enable == false) {
    return;
  }
  int rq_id = e->virtio_layer_info.rq_id;
  auto it = rq_requests.find(rq_id);
  if (it != rq_requests.end()) {
    auto krq = it->second;
    if (krq == nullptr) {
      return;
    }
    auto event = std::unique_ptr<Event>(new Event(e));
    krq->addEvent(std::move(event));
    if (krq->io_statistics.size() > 0)
      krq->io_statistics.back().isVirtIO = true;
  }
}
void IOTracer::HandleQemuEvent(struct event *e) {
  if (config.qemu_enable == false) {
    return;
  }
  int tid = e->qemu_layer_info.tid;
  // 由于一个 qemu 线程可以处理多个异步 io
  // 通过一个 tid 如何定位对应的 request ？
  // qemu_tid_requests[tid] 中列表的 back() 就是当前正在处理的 request
  switch (e->event_type) {
  case qemu__virtio_blk_handle_request: {
    auto qrq = std::make_shared<Request>();
    qrq->setQemuInfo(e);
    auto event = std::unique_ptr<Event>(new Event(e));
    event->trigger_type = trigger_type::ENTRY;
    qrq->addEvent(std::move(event));
    qrq->start_time = e->timestamp;
    auto task_vec_it = qemu_tid_requests.find(tid);
    if (task_vec_it == qemu_tid_requests.end()) {
      qemu_tid_requests.insert(std::make_pair(tid, qemuTaskVector()));
    }
    task_vec_it = qemu_tid_requests.find(tid);
    auto &task_vec = task_vec_it->second;
    task_vec.push_back(std::make_pair(e->qemu_layer_info.virt_rq_addr, qrq));
    break;
  }
  case qemu__virtio_blk_req_complete: {
    auto it = qemu_tid_requests.find(tid);
    if (it != qemu_tid_requests.end()) {
      auto &task_vec = it->second;
      auto task_vec_it = task_vec.begin();
      for (; task_vec_it != task_vec.end(); task_vec_it++) {
        if (task_vec_it->first == e->qemu_layer_info.virt_rq_addr) {
          auto qrq = task_vec_it->second;
          auto event = std::unique_ptr<Event>(new Event(e));
          event->trigger_type = trigger_type::EXIT;
          qrq->addEvent(std::move(event));
          qrq->end_time = e->timestamp;
          task_vec.erase(task_vec_it);
          HandleDoneRequest(qrq);
          break;
        }
      }
    }
    break;
  }
  case qemu__blk_aio_pwritev: {
    if (qemu_tid_requests.find(tid) == qemu_tid_requests.end()) {
      return;
    }
    auto &task_vec = qemu_tid_requests[tid];
    if (task_vec.size() == 0) {
      return;
    }
    auto qrq = task_vec.back().second;
    auto event = std::unique_ptr<Event>(new Event(e));
    qrq->addEvent(std::move(event));
    qrq->qemu_rq_type = RQ_TYPE_WRITE;
    break;
  }
  case qemu__blk_aio_preadv: {
    if (qemu_tid_requests.find(tid) == qemu_tid_requests.end()) {
      return;
    }
    auto &task_vec = qemu_tid_requests[tid];
    if (task_vec.size() == 0) {
      return;
    }
    auto qrq = task_vec.back().second;
    auto event = std::unique_ptr<Event>(new Event(e));
    qrq->addEvent(std::move(event));
    qrq->qemu_rq_type = RQ_TYPE_READ;
    break;
  }
  case qemu__blk_aio_flush: {
    if (qemu_tid_requests.find(tid) == qemu_tid_requests.end()) {
      return;
    }
    auto &task_vec = qemu_tid_requests[tid];
    if (task_vec.size() == 0) {
      return;
    }
    auto qrq = task_vec.back().second;
    auto event = std::unique_ptr<Event>(new Event(e));
    qrq->addEvent(std::move(event));
    qrq->qemu_rq_type = RQ_TYPE_FLUSH;
    break;
  }
  case qemu__qcow2_co_pwritev_part: {
    if (qemu_tid_requests.find(tid) == qemu_tid_requests.end()) {
      return;
    }
    auto &task_vec = qemu_tid_requests[tid];
    if (task_vec.size() == 0) {
      return;
    }
    auto qrq = task_vec.back().second;
    auto event = std::unique_ptr<Event>(new Event(e));
    qrq->addEvent(std::move(event));
    qrq->setQemuInfo(e);
    break;
  }
  case qemu__qcow2_co_preadv_part: {
    if (qemu_tid_requests.find(tid) == qemu_tid_requests.end()) {
      return;
    }
    auto &task_vec = qemu_tid_requests[tid];
    if (task_vec.size() == 0) {
      return;
    }
    auto qrq = task_vec.back().second;
    auto event = std::unique_ptr<Event>(new Event(e));
    qrq->addEvent(std::move(event));
    qrq->setQemuInfo(e);
    break;
  }
  case qemu__qcow2_co_flush_to_os: {
    if (qemu_tid_requests.find(tid) == qemu_tid_requests.end()) {
      return;
    }
    auto &task_vec = qemu_tid_requests[tid];
    if (task_vec.size() == 0) {
      return;
    }
    auto qrq = task_vec.back().second;
    auto event = std::unique_ptr<Event>(new Event(e));
    qrq->addEvent(std::move(event));
    qrq->setQemuInfo(e);
    break;
  }
  case qemu__raw_co_prw: {
    if (qemu_tid_requests.find(tid) == qemu_tid_requests.end()) {
      return;
    }
    auto &task_vec = qemu_tid_requests[tid];
    if (task_vec.size() == 0) {
      return;
    }
    auto qrq = task_vec.back().second;
    auto event = std::unique_ptr<Event>(new Event(e));
    qrq->addEvent(std::move(event));
    qrq->setQemuInfo(e);
    break;
  }
  case qemu__raw_co_flush_to_disk: {
    if (qemu_tid_requests.find(tid) == qemu_tid_requests.end()) {
      return;
    }
    auto &task_vec = qemu_tid_requests[tid];
    if (task_vec.size() == 0) {
      return;
    }
    auto qrq = task_vec.back().second;
    auto event = std::unique_ptr<Event>(new Event(e));
    qrq->addEvent(std::move(event));
    qrq->setQemuInfo(e);
    break;
  }
  case qemu__handle_aiocb_rw: {
    if (e->trigger_type == trigger_type::ENTRY) {
      int prev_id = e->qemu_layer_info.prev_tid;
      if (qemu_tid_requests.find(prev_id) == qemu_tid_requests.end()) {
        return;
      }
      auto &task_vec = qemu_tid_requests[prev_id];
      if (task_vec.size() == 0) {
        return;
      }
      auto qrq = task_vec.back().second;
      auto event = std::unique_ptr<Event>(new Event(e));
      qrq->addEvent(std::move(event));
      requests[tid] = qrq;
    } else if (e->trigger_type == trigger_type::EXIT) {
      auto it = requests.find(tid);
      if (it != requests.end()) {
        auto krq = it->second;
        if (krq == nullptr) {
          return;
        }
        auto event = std::unique_ptr<Event>(new Event(e));
        krq->addEvent(std::move(event));
        requests.erase(it);
      }
    }
    break;
  }
  case qemu__handle_aiocb_flush: {
    if (e->trigger_type == trigger_type::ENTRY) {
      int prev_id = e->qemu_layer_info.prev_tid;
      if (qemu_tid_requests.find(prev_id) == qemu_tid_requests.end()) {
        return;
      }
      auto &task_vec = qemu_tid_requests[prev_id];
      if (task_vec.size() == 0) {
        return;
      }
      auto qrq = task_vec.back().second;
      auto event = std::unique_ptr<Event>(new Event(e));
      qrq->addEvent(std::move(event));
      requests[tid] = qrq;
    } else if (e->trigger_type == trigger_type::EXIT) {
      auto it = requests.find(tid);
      if (it != requests.end()) {
        auto krq = it->second;
        if (krq == nullptr) {
          return;
        }
        auto event = std::unique_ptr<Event>(new Event(e));
        krq->addEvent(std::move(event));
        requests.erase(it);
      }
    }
    break;
  }
  default:
    assert(false);
  }
}
void IOTracer::AddEvent(void *data, size_t data_size) {
  if (data_size != sizeof(struct event)) {
    return;
  }
  struct event *e = (struct event *)data;
  if (e->timestamp < setup_timestamp) {
    return;
  }
  // debug(NULL, data, data_size);
  switch (e->info_type) {
  case syscall_layer: {
    HandleSyscallEvent(e);
    break;
  }
  case fs_layer: {
    HandleFsEvent(e);
    break;
  }
  case block_layer: {
    HandleBlockEvent(e);
    break;
  }
  case sched_layer: {
    HandleSchedEvent(e);
    break;
  }
  case scsi_layer: {
    HandleScsiEvent(e);
    break;
  }
  case nvme_layer: {
    HandleNvmeEvent(e);
    break;
  }
  case virtio_layer: {
    HandleVirtioEvent(e);
    break;
  }
  case qemu_layer: {
    HandleQemuEvent(e);
    break;
  }
  }
}