
// a worklist store pending requests
// vfs
// block

#include "io_analyse.h"
#include "hook_point.h"
#include "io_event.h"
#include <bits/types/FILE.h>
#include <memory>

// class IOEventBuilder : public EventBuilder {
// public:
//   IOEventBuilder() {}
//   ~IOEventBuilder() {}
//   std::shared_ptr<Event> BuildEvent(struct event *e) override;
// };

// std::shared_ptr<Event> IOEventBuilder::BuildEvent(struct event *e) {
//   std::shared_ptr<SyncEvent> event;
//   event = std::make_shared<SyncEvent>();
//   event->event_type = e->event_type;
//   event->timestamp = e->timestamp;

//   if (event->event_type == vfs_read_enter ||
//       event->event_type == vfs_write_enter) {
//   }

//   return event;
// }
double timestamp2ms(unsigned long long timestamp) {
  return timestamp / 1000000.0;
}

void IOEndHandler::HandleDoneRequest(std::unique_ptr<Request> request) {
  assert(outputFile != nullptr);
  IORequest *iorequest = dynamic_cast<IORequest *>(request.get());
  assert(iorequest != nullptr);
  unsigned long long start, end;
  if (auto startEvent =
          dynamic_cast<SyncEvent *>(iorequest->events.front().get())) {
    start = startEvent->timestamp;
    if (startEvent->type != SyncEvent::ENTER) {
      printf("IOEndHandler: request %lld start event is not enter\n",
             iorequest->id);
    }
  } else {
    printf("IOEndHandler: request %lld start event is not sync event\n",
           iorequest->id);
    return;
  }
  if (auto endEvent =
          dynamic_cast<SyncEvent *>(iorequest->events.back().get())) {
    end = endEvent->timestamp;
    if (endEvent->type != SyncEvent::EXIT) {
      printf("IOEndHandler: request %lld end event is not exit\n",
             iorequest->id);
    }
  } else {
    printf("IOEndHandler: request %lld end event is not sync event\n",
           iorequest->id);
    return;
  }
  unsigned long long duration = end - start;
  double duration_ms = timestamp2ms(duration);

  if (duration_ms < config.time_threshold) {
    return;
  }

  int tapnum = 0;
  fprintf(outputFile, "start print request %lld totol time %lf\n",
          iorequest->id, duration_ms);
  for (int i = 0; i < iorequest->events.size(); i++) {
    Event *e = iorequest->events[i].get();
    if (auto syncevent = dynamic_cast<SyncEvent *>(e)) {
      if (syncevent->type == SyncEvent::ENTER) {
        tapnum++;
      }
      for (int k = 0; k < tapnum; k++) {
        fprintf(outputFile, "\t");
      }
      syncevent->printfmt(outputFile);
      fprintf(outputFile, "\n");
      if (syncevent->type == SyncEvent::EXIT) {
        tapnum--;
      }
    } else if (auto asyncevent = dynamic_cast<BlockPendingDuration *>(e)) {
      printf("bio count %d\n", asyncevent->relative_bio.size());
      asyncevent->printfmtNtap(outputFile, tapnum);
    }
  }
  fprintf(outputFile, "end print request %lld\n", iorequest->id);
  request.reset();
}

void IOAnalyser::AddTrace(struct event *e) {
  trace_count++;
  printf("%s\n",kernel_hook_type_str[e->event_type]);
  if (e->info_type == bio_info) {
    if (e->event_type == submit_bio) {
      if (bio_map.find(e->bio_info.bio) != bio_map.end()) {
        printf("bio already exist pid %d, tid %d, comm %s\n", e->pid, e->tid,
               e->comm);
        return;
      }
      auto bio = std::make_shared<BioObject>();
      auto event = std::make_shared<SyncEvent>(e->event_type, e->timestamp,
                                               std::string(e->comm));
      bio_map[e->bio_info.bio] = bio;
      bio->addRelativeEvent(event);
      // find the request
      for (auto &request :
           pending_requests) { // NOTE: make sure pending_requests
                               // will not change during this time
        for (int i = 0; i < e->bio_info.bvec_cnt; i++) {
          if (request->isRelative(e->bio_info.bvecs[i].inode,
                                  e->bio_info.bvecs[i].bv_offset,
                                  e->bio_info.bvecs[i].bv_len)) {
            request->addBioObject(bio);
            break;
          }
        }
      }
    } else {
      if (bio_map.find(e->bio_info.bio) == bio_map.end()) {
        printf("one bio not found pid %d, tid %d, comm %s\n", e->pid, e->tid,
               e->comm);
        return;
      }
      auto bio = bio_map[e->bio_info.bio];
      std::unique_ptr<SyncEvent> event = std::make_unique<SyncEvent>(
          e->event_type, e->timestamp, std::string(e->comm));
      event->type = SyncEvent::EXIT;
      bio->addRelativeEvent(std::move(event));

      if (e->event_type == bio_endio) {
        bio_map.erase(e->bio_info.bio);
      }
    }
  } else if (e->info_type == rq_info) {
    auto event = std::make_shared<SyncEvent>(
        e->event_type, e->timestamp, std::string(e->comm));
    event->type = SyncEvent::EXIT;

    for (int i = 0; i < e->rq_info.relative_bio_cnt; i++) {
      if (bio_map.find(e->rq_info.relative_bios[i]) == bio_map.end()) {
        printf("rq's bio not found pid %d, tid %d, comm %s\n", e->pid, e->tid,
               e->comm);
        continue;
      }
      auto bio = bio_map[e->rq_info.relative_bios[i]];
      bio->addRelativeEvent(event);
    }

  } else {
    if(e->info_type != vfs_layer){
      printf("IOAnalyser::AddTrace: unknown info type %s\n", info_type_str[e->info_type]);
      assert(false);
    }
    std::unique_ptr<SyncEvent> event = std::make_unique<SyncEvent>(
        e->event_type, e->timestamp, std::string(e->comm));

    bool createNewRequest = false;
    bool endRequest = false;
    int indexDone = -1;
    if (e->event_type == vfs_read_enter || e->event_type == vfs_write_enter) {
      event->type = SyncEvent::ENTER;
      createNewRequest = true;
    } else if (e->event_type == vfs_read_exit ||
               e->event_type == vfs_write_exit) {
      event->type = SyncEvent::EXIT;
      endRequest = true;
    }

    IORequest *io_request = nullptr;
    if (createNewRequest) {
      std::unique_ptr<IORequest> request = std::make_unique<IORequest>(
          e->pid, e->tid, e->vfs_layer_info.inode, e->vfs_layer_info.dev,
          e->vfs_layer_info.file_offset, e->vfs_layer_info.file_bytes);
      io_request = request.get();
      AddRequest(std::move(request));
    } else {
      for (int i = 0; i < pending_requests.size(); i++) {
        IORequest *request =
            dynamic_cast<IORequest *>(pending_requests[i].get());
        assert(request != nullptr);
        bool relative = true;
        relative = request->isRelative(e->vfs_layer_info.inode,
                                          e->vfs_layer_info.file_offset,
                                          e->vfs_layer_info.file_bytes);
        if (relative) {
          if (endRequest) {
            indexDone = i;
          }
          io_request = request;
          break;
        }
      }
    }

    if(io_request != nullptr) {
      io_request->AddEvent(std::move(event));
    }

    if (indexDone != -1) {
      EndRequest(indexDone);
    }
  }
}