#pragma once

#include "bpf/bpf.h"
#include "analyse.h"
#include "basic_event.h"
#include "cstdio"
#include "event_defs.h"
#include "hook_point.h"
#include "io_event.h"
#include "iotrace.skel.h"
#include "vector"
#include <bpf/libbpf.h>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <stddef.h>
#include <utility>
#include <vector>

class IOEndHandler : public DoneRequestHandler {
public:
  IOEndHandler(TraceConfig &&config) : DoneRequestHandler(std::move(config)) {
    std::filesystem::path &output_path = this->config.output_path;
    printf("IOEndHandler: open output file %s\n", output_path.c_str());
    if (!output_path.empty()) {
      outputFile = fopen(output_path.c_str(), "w");
      if (outputFile == nullptr) {
        printf("IOEndHandler: open output file failed\n");
        outputFile = stdout;
      }
    } else {
      outputFile = stdout;
    }
  }

  ~IOEndHandler() {
    if (outputFile != stdout) {
      fclose(outputFile);
    }
  }

  void readAbsPath(unsigned long long inode, std::string &path,struct abs_path &abs_path) {
    // get abs path from bpf map
    struct iotrace_bpf *skel = config.skel;
    path = "";
    for (int level = 0; level < MAX_LEVEL; level++) {
      if (abs_path.name[level][0] == '\0' ) {
        continue;
      }
      // if(abs_path.name[level][0] == '/') {
      //   path = abs_path.name[level];
      //   continue;
      // }else{
      // path += "/";
      // }
      if(abs_path.has_root){
        path += "/";
        path += abs_path.name[level];
      }
    }
    // printf("abs path for inode %lld is %s\n", inode, path.c_str());
  }

  void addInfo(void* data, size_t data_size) override;
  void HandleDoneRequest(std::shared_ptr<Request>) override;
  FILE *outputFile;
  std::map<unsigned long long, std::string> inode_abs_path_map;
};

class IOAnalyser : public Analyser {
public:
  IOAnalyser(std::unique_ptr<DoneRequestHandler> handler)
      : Analyser(std::move(handler)) {}
  ~IOAnalyser() {}
  void processVfsEntry(struct event *&e, std::unique_ptr<SyncEvent> &event);
  void AddTrace(void *data, size_t data_size) override;
  void AddRequest(std::shared_ptr<IORequest> request) {
    pending_requests.push_back(std::move(request));
  }
  void EndRequest(int idx) {
    std::shared_ptr<IORequest> request = std::move(pending_requests[idx]);
    pending_requests.erase(pending_requests.begin() + idx);
    // printf("IOAnalyser: request %lld end\n", request->id);
    Analyser::DoneRequest(std::move(request));
  }

  void AddRequestObject(unsigned long long rq,
                        unsigned long long request_queue) {
    if (request_queue_map.find(request_queue) == request_queue_map.end()) {
      request_queue_map[request_queue] = std::make_shared<RequestQueueObject>();
    }

    if (request_map.find(rq) == request_map.end()) {
      request_map[rq] = std::make_shared<RequestObject>();
    }

    auto request_queue_object = request_queue_map[request_queue];
    auto request_object = request_map[rq];
    request_queue_object->request_objects.push_back(std::move(request_object));
  }

  // must have bio queue or split first
  bool addBioRqAssociation(
      unsigned long long bio,
      unsigned long long rq, // for add bio to request, merge bio with request
      unsigned long long request_queue) {
    if (bio_map.find(bio) == bio_map.end()) {
      return false;
    }

    if (request_map.find(rq) == request_map.end()) {
      AddRequestObject(rq, request_queue);
    }
    auto request_object = request_map[rq];
    auto bio_object = bio_map[bio];
    request_object->bio_objects.push_back(std::move(bio_object));
    return true;
  }

  bool deleteBioRqAssociation(unsigned long long bio,
                              unsigned long long rq, // block_rq_complete
                              unsigned long long request_queue) {
    if (bio_map.find(bio) == bio_map.end()) {
      return false;
    }
    bio_map.erase(bio);
    return true;
    // leave bio_object weak ptr in request_object
  }

  bool deleteRequestObject(unsigned long long rq,
                           unsigned long long request_queue) {
    if (request_map.find(rq) == request_map.end()) {
      return false;
    }
    request_map.erase(rq);
    return true;
    // leave request_object weak ptr in request_queue_object
  }

  void processBioQueue1(unsigned long long bio, unsigned long bio_op) {
    // 覆盖
    auto bio_object = std::make_shared<BioObject>();
    bio_object->setBioOp(bio_op);
    bio_map[bio] = bio_object;
    // add bio but not with bvec
  }

  bool processBioQueue2(unsigned long long bio,
                        struct bvec_array_info *bvec_info) {
    if (bio_map.find(bio) == bio_map.end()) {
      return false;
    }
    auto bio_object = bio_map[bio];
    assert(bio_object->parent.get() == 0);
    for (int i = 0; i < bvec_info->bvec_cnt; i++) {
      auto inode = bvec_info->bvecs[i].inode;
      auto offset =
          (bvec_info->bvecs[i].index << 12) + bvec_info->bvecs[i].bv_offset;
      auto len = bvec_info->bvecs[i].bv_len;
      bio_object->addAssociation(inode, offset, len);
    }
    // add bio to relative request
    for (auto &io_request : pending_requests) {
      io_request->AddBioObjectAndBuildMapping(bio_object, io_request);
    }
    return true;
  }

  bool processBioSplit(unsigned long long bio, unsigned long long parent_bio,
                       unsigned short bvec_idx_start,
                       unsigned short bvec_idx_end) {
    if (bio_map.find(parent_bio) == bio_map.end()) {
      return false;
    }
    auto parent_bio_object = bio_map[parent_bio];
    // if (bio_map.find(bio) != bio_map.end()) {
    //   return false;
    // }
    auto child_bio_object = std::make_shared<BioObject>(); // update bio_map
    child_bio_object->parent = parent_bio_object;
    child_bio_object->setBioOp(parent_bio_object->bio_op);
    bio_map[bio] = child_bio_object;
    // add bio to relative request base on bvec_idx
    bvec_idx_end = bvec_idx_end >= parent_bio_object->associations.size()
                       ? parent_bio_object->associations.size() - 1
                       : bvec_idx_end;
    // printf("bvec_idx_start %d, bvec_idx_end %d\n", bvec_idx_start,
    //        bvec_idx_end);
    // printf("parent_bio_object->associations.size() %ld\n",
    //  parent_bio_object->associations.size());
    for (int i = bvec_idx_start; i <= bvec_idx_end; i++) {
      auto &association = parent_bio_object->associations[i];
      for (auto &request_object : association.relative_requests) {
        // assert(request_object.expired() == false && "request not done yet");
        if (request_object.expired()) {
          continue;
        }
        auto request = request_object.lock();
        auto io_request = std::dynamic_pointer_cast<IORequest>(request);
        io_request->addBioObject(child_bio_object);
      }
    }
    return true;
  }

  bool addEventToBio(unsigned long long bio, std::shared_ptr<SyncEvent> event) {
    if (bio_map.find(bio) == bio_map.end()) {
      return false;
    }
    auto bio_object = bio_map[bio];
    bio_object->addRelativeEvent(event);
    return true;
  }

  bool addEventToRequest(unsigned long long rq,
                         std::shared_ptr<SyncEvent> event) {
    if (request_map.find(rq) == request_map.end()) {
      return false;
    }
    auto request_object = request_map[rq];
    request_object->addEvent(event);
    return true;
  }

  bool addEventToRequestQueue(unsigned long long request_queue,
                              std::shared_ptr<SyncEvent> event) {
    if (request_queue_map.find(request_queue) == request_queue_map.end()) {
      return false;
    }

    auto &request_queue_object = request_queue_map[request_queue];
    // assert(request_queue_object != nullptr && "can not find request queue
    // object");
    request_queue_object->addEvent(event);
    return true;
  }

  struct RequestObject {
    std::vector<std::weak_ptr<BioObject>> bio_objects;
    void addEvent(std::shared_ptr<SyncEvent> event) {
      std::vector<int> rmIndex = {};
      for (int i = 0; i < bio_objects.size(); i++) {
        if (bio_objects[i].expired()) {
          rmIndex.push_back(i);
        } else {
          auto bio = bio_objects[i].lock();
          if (!bio->bioIsDone()) {
            bio->addRelativeEvent(event);
          } else {
            rmIndex.push_back(i); // bio is done, remove the ptr
          }
        }
      }
      for (int i = rmIndex.size() - 1; i >= 0; i--) {
        bio_objects.erase(bio_objects.begin() + rmIndex[i]);
      }
    }
  };
  struct RequestQueueObject {
    std::vector<std::weak_ptr<RequestObject>> request_objects;
    void addEvent(std::shared_ptr<SyncEvent> event) {
      std::vector<int> rmIndex = {};
      for (int i = 0; i < request_objects.size(); i++) {
        if (request_objects[i].expired()) {
          rmIndex.push_back(i);
        } else {
          auto request = request_objects[i].lock();
          request->addEvent(event);
        }
      }
      for (int i = rmIndex.size() - 1; i >= 0; i--) {
        request_objects.erase(request_objects.begin() + rmIndex[i]);
      }
    }
  };
  std::vector<std::shared_ptr<IORequest>> pending_requests;
  std::map<unsigned long long, std::shared_ptr<BioObject>> bio_map;
  std::map<unsigned long long, std::shared_ptr<RequestObject>> request_map;
  std::map<unsigned long long, std::shared_ptr<RequestQueueObject>>
      request_queue_map;

  // statics
  unsigned long long trace_count = 0;
  unsigned long long trace_unhandle = 0;
};