#include "iotracer.h"
#include "basic_types.h"
#include "event_defs.h"
#include "hook_point.h"
#include <cassert>
#include <cstddef>
#include <ctime>
#include <memory>

void IOTracer::HandleBlockEvent(struct event *e) {
  if (e->event_type == kernel_hook_type::block__bio_queue) {
    int tid = e->block_layer_info.tid;
    int pid = e->block_layer_info.tgid;
    int bio_id = e->block_layer_info.bio_id;
    auto krq = requests[tid];
    if(krq == nullptr){
      return;
    }
    auto event = std::unique_ptr<Event>(new Event(e));
    krq->addEvent(std::move(event));
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
  } else if (e->event_type == kernel_hook_type::block__bio_bounce ||
             e->event_type == kernel_hook_type::block__bio_throttle ||
             e->event_type == kernel_hook_type::block__bio_bounce) {
    int bio_id = e->block_layer_info.bio_id;
    auto it = bio_requests.find(bio_id);
    if (it != bio_requests.end()) {
      auto krq = it->second;
      auto event = std::unique_ptr<Event>(new Event(e));
      krq->addEvent(std::move(event));
    }
  } else if (e->event_type == kernel_hook_type::block__rq_insert ||
             e->event_type == kernel_hook_type::block__rq_issue ||
             e->event_type == kernel_hook_type::block__rq_requeue) {
    int rq_id = e->block_layer_info.rq_id;
    auto it = rq_requests.find(rq_id);
    if (it != rq_requests.end()) {
      auto krq = it->second;
      auto event = std::unique_ptr<Event>(new Event(e));
      krq->addEvent(std::move(event));
    } 
  }else{
    assert(false);
  }
}

  void IOTracer::AddEvent(void *data, size_t data_size) {
  // debug(NULL,data,0);
    if (data_size != sizeof(struct event)) {
      return;
    }
    struct event *e = (struct event *)data;
    switch (e->info_type) {
    case syscall_layer: {
      int tid = e->syscall_layer_info.tid;
      int pid = e->syscall_layer_info.tgid;
      if (e->trigger_type == trigger_type::ENTRY) {
        auto krq = std::make_shared<Request>();
        krq->setSyscallInfo(e);
        krq->start_time = e->timestamp;
        requests[tid] = krq;
        auto event = std::unique_ptr<Event>(new Event(e));
        krq->addEvent(std::move(event));
      } else if (e->trigger_type == trigger_type::EXIT) {
        int ret = e->syscall_layer_info.ret;
        auto it = requests.find(tid);
        if (it != requests.end()) {
          auto krq =it->second;
          auto event = std::unique_ptr<Event>(new Event(e));
          krq->addEvent(std::move(event));
          krq->setRet(ret);
          krq->end_time = e->timestamp;
          HandleDoneRequest(krq);
          requests.erase(it);
        } 
      } else {
        assert(false);
      }
      break;
    }
    case fs_layer: {
      int tid = e->fs_layer_info.tid;
      int pid = e->fs_layer_info.tgid;
      auto krq = requests[tid];
      if(krq == nullptr){
        break;
      }
      if (e->trigger_type != trigger_type::EXIT) {
        unsigned long offset = e->fs_layer_info.offset;
        unsigned long bytes = e->fs_layer_info.bytes;
        krq->setSyscallRange(offset, bytes);
      }
      auto event = std::unique_ptr<Event>(new Event(e));
      krq->addEvent(std::move(event));
      break;
    }
    case block_layer: {
      HandleBlockEvent(e);
      break;
    }
    case sched_layer: {
      int prev_tid = e->sched_layer_info.prev_tid;
      int next_tid = e->sched_layer_info.next_tid;

      auto it = requests.find(prev_tid);
      if (it != requests.end()) {
        auto krq =it->second;
        auto event = std::unique_ptr<Event>(new Event(e));
        event->trigger_type = trigger_type::ENTRY;
        krq->addEvent(std::move(event));
      }

      it = requests.find(next_tid);
      if (it != requests.end()) {
        auto krq = it->second;
        auto event = std::unique_ptr<Event>(new Event(e));
        event->trigger_type = trigger_type::EXIT;
        krq->addEvent(std::move(event));
      }
      break;
    }
    case scsi_layer: {
      int rq_id = e->scsi_layer_info.rq_id;
      auto it = rq_requests.find(rq_id);
      if (it != rq_requests.end()) {
        auto krq = it->second;
        auto event = std::unique_ptr<Event>(new Event(e));
        krq->addEvent(std::move(event));
      } 
      break;
    }
    case nvme_layer: {
      int rq_id = e->nvme_layer_info.rq_id;
      auto it = rq_requests.find(rq_id);
      if (it != rq_requests.end()) {
        auto krq = it->second;
        auto event = std::unique_ptr<Event>(new Event(e));
        krq->addEvent(std::move(event));
      }
      break;
    }
    case virtio_layer: {
      if(config.virtio_enable == false){
        break;
      }
      int rq_id = e->virtio_layer_info.rq_id;
      int sector = e->virtio_layer_info.sector;
      int nr_bytes = e->virtio_layer_info.nr_bytes;
      auto it = rq_requests.find(rq_id);
      if (it != rq_requests.end()) {
        auto krq = it->second;
        auto event = std::unique_ptr<Event>(new Event(e));
        krq->addEvent(std::move(event));
        krq->setVirtioRange(sector, nr_bytes);
      } 
      break;
    }
    case qemu_layer: {
      if(config.qemu_enable == false){
        break;
      }
      break;
    }
    }
  }