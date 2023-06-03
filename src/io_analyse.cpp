#include "io_analyse.h"
#include "event_defs.h"
#include "hook_point.h"
#include "io_event.h"
#include <bits/types/FILE.h>
#include <cstddef>
#include <memory>

double timestamp2ms(unsigned long long timestamp) {
  return timestamp / 1000000.0;
}

void IOEndHandler::HandleDoneRequest(std::shared_ptr<Request> request) {
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
      fprintf(outputFile,"bio count %ld\n", asyncevent->relative_bio.size());
      asyncevent->printfmtNtap(outputFile, tapnum);
    }
  }
  fprintf(outputFile, "end print request %lld\n", iorequest->id);
  request.reset();
}

void IOAnalyser::AddTrace(void *data, size_t data_size) {
  if (data_size == sizeof(struct bvec_array_info)) {
    // printf("IOAnalyser::AddTrace: bvec_array_info, bvec cnt %u\n",
    //        ((struct bvec_array_info *)data)->bvec_cnt);
    struct bvec_array_info *bvec_info = (struct bvec_array_info *)data;
    processBioQueue2(bvec_info->bio, bvec_info);
  } else if (data_size == sizeof(struct event)) {
    struct event *e = (struct event *)data;
    // printf("IOAnalyser::AddTrace: event type %s comm %s\n",
    //        kernel_hook_type_str[e->event_type], e->comm);
    auto event = std::make_shared<SyncEvent>(e->event_type, e->timestamp,
                                             std::string(e->comm));
    if (e->info_type == bio_rq_association_info) {
      if (e->event_type == rq_qos_track || e->event_type == rq_qos_merge) {
        addBioRqAssociation(e->bio_rq_association_info.bio,
                            e->bio_rq_association_info.rq,
                            e->bio_rq_association_info.request_queue);
        addEventToBio(e->bio_rq_association_info.bio, event);
      } else if (e->event_type == block_rq_complete) {
        addEventToBio(e->bio_rq_association_info.bio, event);
        deleteBioRqAssociation(e->bio_rq_association_info.bio,
                               e->bio_rq_association_info.rq,
                               e->bio_rq_association_info.request_queue);
      } else {
        printf("IOAnalyser::AddTrace: unknown event type %s\n",
               kernel_hook_type_str[e->event_type]);
        assert(false);
      }
    } else if (e->info_type == rq_info) {
      auto event = std::make_shared<SyncEvent>(e->event_type, e->timestamp,
                                               std::string(e->comm));
      if (e->event_type == block_rq_insert || e->event_type == block_rq_issue || e->event_type == rq_qos_requeue) {
        addEventToRequest(e->rq_info.rq, event);
      } else if (e->event_type == rq_qos_done) {
        addEventToRequest(e->rq_info.rq, event);
        deleteRequestObject(e->rq_info.rq,e->rq_info.request_queue);
      } else {
        printf("IOAnalyser::AddTrace: unknown event type %s\n",
               kernel_hook_type_str[e->event_type]);
        assert(false);
      }
    } else if (e->info_type == bio_info) {
      auto event = std::make_shared<SyncEvent>(e->event_type, e->timestamp,
                                               std::string(e->comm));
      if (e->event_type == block_bio_queue) {
        processBioQueue1(e->bio_info.bio,e->bio_info.bio_op);
        addEventToBio(e->bio_info.bio, event);
      } else if (e->event_type == block_split) {
        processBioSplit(e->bio_info.bio, e->bio_info.parent_bio,
                        e->bio_info.bvec_idx_start, e->bio_info.bvec_idx_end);
        addEventToBio(e->bio_info.bio, event);
      } else {
        printf("IOAnalyser::AddTrace: unknown event type %s\n",
               kernel_hook_type_str[e->event_type]);
        assert(false);
      }
    } else if (e->info_type == rq_plug_info) {
      auto event = std::make_shared<SyncEvent>(e->event_type, e->timestamp,
                                               std::string(e->comm));
      if (e->event_type == block_plug || e->event_type == block_unplug) {
        addEventToRequestQueue(e->rq_plug_info.request_queue, event);
      }
    } else if (e->info_type == vfs_layer) {
      std::unique_ptr<SyncEvent> event = std::make_unique<SyncEvent>(
          e->event_type, e->timestamp, std::string(e->comm));
      if (e->event_type == vfs_read_enter || e->event_type == vfs_write_enter) {
        event->type = SyncEvent::ENTER;
        auto io_request = std::make_shared<IORequest>(
            e->pid, e->tid, e->vfs_layer_info.inode, e->vfs_layer_info.dev,
            e->vfs_layer_info.file_offset, e->vfs_layer_info.file_bytes);
        AddRequest(io_request);
        if (io_request != nullptr) {
          io_request->AddEvent(std::move(event));
        }
      } else if (e->event_type == vfs_read_exit ||
                 e->event_type == vfs_write_exit) {
        event->type = SyncEvent::EXIT;
        for (int i = pending_requests.size()-1; i >= 0; i--) {
          auto io_request = pending_requests[i];
          if (io_request->isEqual(e->vfs_layer_info.inode,
                                  e->vfs_layer_info.file_offset,
                                  e->vfs_layer_info.file_bytes)) {
            io_request->AddEvent(std::move(event));
            EndRequest(i);
            break;
          }
        }
      }
    }
  } else {
    printf("unknown data struct\n");
    assert(false);
  }
}