#include "io_analyse.h"
#include "event_defs.h"
#include "hook_point.h"
#include "io_event.h"
#include <bits/types/FILE.h>
#include <cstddef>
#include <ctime>
#include <memory>

double timestamp2ms(unsigned long long timestamp) {
  return timestamp / 1000000.0;
}

void IOEndHandler::addInfo(void *data, size_t data_size) {
  if (data_size == sizeof(struct abs_path)) {
    struct abs_path *abs_path = (struct abs_path *)data;
    // printf("IOAnalyser::AddTrace: abs_path %s\n", path->path);
    std::string path;
    readAbsPath(abs_path->inode, path, *abs_path);
    inode_abs_path_map[abs_path->inode] = path;
  }
}

void IOEndHandler::HandleDontPrintRequest(std::shared_ptr<Request> request) {
  auto iorequest = std::dynamic_pointer_cast<IORequest>(request);
  statistic_mutex.lock();
  for (int i = 0; i < iorequest->events.size(); i++) {
    Event *e = iorequest->events[i].get();
    if (auto syncevent = dynamic_cast<SyncEvent *>(e)) {
      auto enterIter = event_pair_map.find(syncevent->event_type);
      if (enterIter != event_pair_map.end()) {
        event_pair_occur_map[enterIter->second] =
            syncevent->timestamp; // store enter's timestamp to exit event
      } else {
        // printf("exit event1: %s\n",
        // kernel_hook_type_str[syncevent->event_type]);
        auto exitIter = event_pair_occur_map.find(syncevent->event_type);
        if (exitIter != event_pair_occur_map.end()) {
          updateStatistic(syncevent->event_type, syncevent->timestamp,
                          exitIter->second, iorequest->type);
          event_pair_occur_map.erase(exitIter);
        }
      }
    } else if (auto asyncevent = dynamic_cast<BlockPendingDuration *>(e)) {
      for (auto &bio : asyncevent->relative_bio) {
        // assert(false);
        for (auto &syncevent : bio->relative_events) { // FIXME: refactor
        // printf("type:%s",kernel_hook_type_str[syncevent->event_type]);
          // is the end of some duration?
          bool isExitToo = false;
          auto enterIter = event_pair_map.find(syncevent->event_type);
          auto exitIter = event_pair_occur_map.find(syncevent->event_type);
          if (exitIter != event_pair_occur_map.end()) {
            isExitToo = true;
            updateStatistic(syncevent->event_type, syncevent->timestamp,
                            exitIter->second, iorequest->type);
            event_pair_occur_map.erase(exitIter);
          }

          if (enterIter != event_pair_map.end()) {
            event_pair_occur_map[enterIter->second] =
                syncevent->timestamp; // store enter's timestamp
          }
        }
      }
    }
  }
  statistic_mutex.unlock();
  request.reset();
}

void IOEndHandler::HandleDoneRequest(std::shared_ptr<Request> request) {
  IORequest *iorequest = dynamic_cast<IORequest *>(request.get());
  unsigned long long start, end;
  if (auto startEvent =
          dynamic_cast<SyncEvent *>(iorequest->events.front().get())) {
    start = startEvent->timestamp;
  } else {
    return;
  }

  if (auto endEvent =
          dynamic_cast<SyncEvent *>(iorequest->events.back().get())) {
    end = endEvent->timestamp;
  } else {
    return;
  }

  unsigned long long duration = end - start;
  double duration_ms = timestamp2ms(duration);

  if (duration_ms < config.time_threshold) {
    HandleDontPrintRequest(request);
    return;
  }
  int tapnum = 0;
//   if (inode_abs_path_map.find(iorequest->inode) == inode_abs_path_map.end()) {
//     fprintf(outputFile,
//             "task %s  request %lld total time %lf \ttarget file inode %lld "
//             "path %s\n",
//             iorequest->comm.c_str(), iorequest->id, duration_ms,
//             iorequest->inode, "unknown");
//   } else {
//     fprintf(outputFile,
//             "task %s  request %lld total time %lf \ttarget file inode %lld "
//             "path %s\n",
//             iorequest->comm.c_str(), iorequest->id, duration_ms,
//             iorequest->inode, inode_abs_path_map[iorequest->inode].c_str());
//   }
    fprintf(outputFile,
            "task %s  request %lld total time %lf \ttarget file inode %lld \n",
            iorequest->comm.c_str(), iorequest->id, duration_ms,
            iorequest->inode);

  std::string tapstr = "";
  statistic_mutex.lock();
  for (int i = 0; i < iorequest->events.size(); i++) {
    Event *e = iorequest->events[i].get();
    if (auto syncevent = dynamic_cast<SyncEvent *>(e)) {
      // printf("sync event: %s\n",
      // kernel_hook_type_str[syncevent->event_type]); first print the time
      // stamp since start
      auto enterIter = event_pair_map.find(syncevent->event_type);
      if (enterIter != event_pair_map.end()) {
        event_pair_occur_map[enterIter->second] =
            syncevent->timestamp; // store enter's timestamp to exit event
        tapstr.push_back('\t');
        // printf("enter event: %s\n",
        // kernel_hook_type_str[syncevent->event_type]);
        fprintf(outputFile, "%-10f ms%s%s {\n",
                timestamp2ms(syncevent->timestamp - start), tapstr.c_str(),
                kernel_hook_type_str[syncevent->event_type]);
        // printf("enter event1: %s\n",
        // kernel_hook_type_str[syncevent->event_type]);
      } else {
        if (syncevent->type == SyncEvent::ENTER) {
        normal_print:
          // like mark_page_accessed
          // just print the time since start and exit event
          fprintf(outputFile, "%-10f ms%s%s\n",
                  timestamp2ms(syncevent->timestamp - start), tapstr.c_str(),
                  kernel_hook_type_str[syncevent->event_type]);
        } else {
          // printf("exit event1: %s\n",
          // kernel_hook_type_str[syncevent->event_type]);
          auto exitIter = event_pair_occur_map.find(syncevent->event_type);
          if (exitIter != event_pair_occur_map.end()) {
            // find the corresponding enter event
            // printf("exit event2: %s\n",
            // kernel_hook_type_str[syncevent->event_type]);
            fprintf(outputFile, "%-10f ms%s} %s\n",
                    timestamp2ms(syncevent->timestamp - start), tapstr.c_str(),
                    kernel_hook_type_str[syncevent->event_type]);
            tapstr.pop_back();
            updateStatistic(syncevent->event_type, syncevent->timestamp,
                            exitIter->second, iorequest->type);
            event_pair_occur_map.erase(exitIter);
          } else {
            goto normal_print;
          }
        }
      }
    } else if (auto asyncevent = dynamic_cast<BlockPendingDuration *>(e)) {
      for (auto &bio : asyncevent->relative_bio) {
        if (!bio->bioIsDone()) {
          continue;
        }
        // assert(false);
        for (auto &syncevent : bio->relative_events) { // FIXME: refactor
          // is the end of some duration?
          bool isExitToo = false;
          auto enterIter = event_pair_map.find(syncevent->event_type);
          auto exitIter = event_pair_occur_map.find(syncevent->event_type);
          if (exitIter != event_pair_occur_map.end()) {
            isExitToo = true;
            // find the corresponding enter event
            if (enterIter != event_pair_map.end()) {
              fprintf(outputFile, "%-10f ms%s} %s {\n",
                      timestamp2ms(syncevent->timestamp - start),
                      tapstr.c_str(),
                      kernel_hook_type_str[syncevent->event_type]);
            } else {
              fprintf(outputFile, "%10f ms%s} %s\n",
                      timestamp2ms(syncevent->timestamp - start),
                      tapstr.c_str(),
                      kernel_hook_type_str[syncevent->event_type]);
            }
            tapstr.pop_back();
            updateStatistic(syncevent->event_type, syncevent->timestamp,
                            exitIter->second, iorequest->type);
            event_pair_occur_map.erase(exitIter);
          }
          // first print the time stamp since start
          // printf("sync event 2: %s\n",
          // kernel_hook_type_str[syncevent->event_type]);
          if (enterIter != event_pair_map.end()) {
            event_pair_occur_map[enterIter->second] =
                syncevent->timestamp; // store enter's timestamp
            tapstr.push_back('\t');
            if (!isExitToo) {
              fprintf(outputFile, "%-10f ms%s%s {\n",
                      timestamp2ms(syncevent->timestamp - start),
                      tapstr.c_str(),
                      kernel_hook_type_str[syncevent->event_type]);
            }
          } else {
            // like mark_page_accessed
            // just print the time since start and exit event
            if (!isExitToo) {
              fprintf(outputFile, "%-10f ms%s%s\n",
                      timestamp2ms(syncevent->timestamp - start),
                      tapstr.c_str(),
                      kernel_hook_type_str[syncevent->event_type]);
            }
          }
        }
      }
    }
  }
  statistic_mutex.unlock();
  fprintf(outputFile, "end print request %lld\n", iorequest->id);
  request.reset();
}

void IOAnalyser::processVfsExit(struct event *&e,
                                std::unique_ptr<SyncEvent> &event) {
  event->type = SyncEvent::EXIT;
  for (int i = pending_requests.size() - 1; i >= 0; i--) {
    auto io_request = pending_requests[i];
    if (io_request->isRelative(e->pid, e->tid, e->vfs_layer_info.inode,
                               e->vfs_layer_info.file_offset,
                               e->vfs_layer_info.file_bytes)) {
      io_request->AddEvent(std::move(event));
      EndRequest(i);
      break;
    }
  }
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
      if (e->event_type == block_rq_insert || e->event_type == block_rq_issue ||
          e->event_type == rq_qos_requeue) {
        addEventToRequest(e->rq_info.rq, event);
      } else if (e->event_type == rq_qos_done) {
        addEventToRequest(e->rq_info.rq, event);
        deleteRequestObject(e->rq_info.rq, e->rq_info.request_queue);
      } else {
        printf("IOAnalyser::AddTrace: unknown event type %s\n",
               kernel_hook_type_str[e->event_type]);
        assert(false);
      }
    } else if (e->info_type == bio_info) {
      auto event = std::make_shared<SyncEvent>(e->event_type, e->timestamp,
                                               std::string(e->comm));
      if (e->event_type == block_bio_queue) {
        processBioQueue1(e->bio_info.bio, e->bio_info.bio_op);
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
        enum IORequest::requestType type;
        if (e->event_type == vfs_read_enter) {
          type = IORequest::READ;
        } else {
          type = IORequest::WRITE;
        }
        auto io_request = std::make_shared<IORequest>(
            e->pid, e->tid, e->vfs_layer_info.inode, e->vfs_layer_info.dev,
            e->vfs_layer_info.file_offset, e->vfs_layer_info.file_bytes,
            std::string(e->comm), type);
        AddRequest(io_request);
        io_request->AddEvent(std::move(event));
      } else if (e->event_type == vfs_read_exit ||
                 e->event_type == vfs_write_exit) {
        processVfsExit(e, event);
      } else if (e->event_type == filemap_get_pages_enter ||
                 e->event_type == filemap_range_needs_writeback_enter ||
                 e->event_type == filemap_write_and_wait_range_enter ||
                 e->event_type == mark_page_accessed ||
                 e->event_type == iomap_dio_rw_enter ||
                 e->event_type == __cond_resched_enter) {
        event->type = SyncEvent::ENTER;
        for (int i = pending_requests.size() - 1; i >= 0; i--) {
          auto io_request = pending_requests[i];
          if (io_request->isRelative(e->pid, e->tid, e->vfs_layer_info.inode,
                                     e->vfs_layer_info.file_offset,
                                     e->vfs_layer_info.file_bytes)) {
            io_request->AddEvent(std::move(event));
            break;
          }
        }

      } else if (e->event_type == filemap_get_pages_exit ||
                 e->event_type == filemap_range_needs_writeback_exit ||
                 e->event_type == filemap_write_and_wait_range_exit ||
                 e->event_type == iomap_dio_rw_exit ||
                 e->event_type == __cond_resched_exit) {
        event->type = SyncEvent::EXIT;
        for (int i = pending_requests.size() - 1; i >= 0; i--) {
          auto io_request = pending_requests[i];
          if (io_request->isRelative(e->pid, e->tid, e->vfs_layer_info.inode,
                                     e->vfs_layer_info.file_offset,
                                     e->vfs_layer_info.file_bytes)) {
            io_request->AddEvent(std::move(event));
            break;
          }
        }
      }
    }
  } else if (data_size == sizeof(struct abs_path)) {
    done_request_handler->addInfo(data, data_size);
  } else {
    printf("unknown data struct\n");
    assert(false);
  }
}