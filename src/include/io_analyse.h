#pragma once

#include "analyse.h"
#include "basic_event.h"
#include "cstdio"
#include "event_defs.h"
#include "hook_point.h"
#include "io_event.h"
#include "vector"
#include <cstdio>
#include <map>
#include <memory>
#include <stddef.h>
#include <utility>
#include <vector>

class IOEndHandler : public DoneRequestHandler {
public:
  IOEndHandler(TraceConfig config) : DoneRequestHandler(std::move(config)) {
    std::filesystem::path &output_path = config.output_path;
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
  void HandleDoneRequest(std::shared_ptr<Request>) override;
  FILE *outputFile;
};

class IOAnalyser : public Analyser {
public:
  IOAnalyser(std::unique_ptr<DoneRequestHandler> handler)
      : Analyser(std::move(handler)) {}
  ~IOAnalyser() {}
  void AddTrace(void *data, size_t data_size) override;
  void AddRequest(std::shared_ptr<IORequest> request) {
    pending_requests.push_back(std::move(request));
  }
  void EndRequest(int idx) {
    std::shared_ptr<IORequest> request = std::move(pending_requests[idx]);
    pending_requests.erase(pending_requests.begin() + idx);
    printf("IOAnalyser: request %lld end\n", request->id);
    Analyser::DoneRequest(std::move(request));
  }

  void AddRequestObject(unsigned long long rq,
                        unsigned long long request_queue) {
    auto &request_queue_object = request_queue_map[request_queue];
    if (request_queue_object == nullptr) {
      request_queue_object = std::make_shared<RequestQueueObject>();
    }
    auto &request_object = request_map[rq];
    if (request_object == nullptr) {
      request_object = std::make_shared<RequestObject>();
    }
    request_queue_object->request_objects.push_back(std::move(request_object));
  }

  void addBioRqAssociation(
      unsigned long long bio,
      unsigned long long rq, // for add bio to request, merge bio with request
      unsigned long long request_queue) {
    auto &bio_object = bio_map[bio];
    if (bio_object == nullptr) {
      bio_object = std::make_shared<BioObject>();
      assert(false && "can not find bio object");
    }
    if (request_map.find(rq) == request_map.end()) {
      AddRequestObject(rq, request_queue);
    }
    auto request_object = request_map[rq];
    request_object->bio_objects.push_back(std::move(bio_object));
  }

  void deleteBioRqAssociation(unsigned long long bio,
                              unsigned long long rq, // block_rq_complete
                              unsigned long long request_queue) {
    auto &bio_object = bio_map[bio];
    if (bio_object == nullptr) {
      assert(false && "can not find bio object");
    }
    auto &request_object =
        request_map[rq]; // TODO: will not change request when it enters one
    if (request_object == nullptr) {
      assert(false && "can not find request object");
    }
    bio_map.erase(bio);
    // leave bio_object weak ptr in request_object
  }

  void deleteRequestObject(unsigned long long rq,
                           unsigned long long request_queue) {
    auto &request_object = request_map[rq];
    if (request_object == nullptr) {
      assert(false && "can not find request object");
    }
    request_map.erase(rq);
    // leave request_object weak ptr in request_queue_object
  }

  void processBioQueue1(unsigned long long bio) {
    auto &bio_object = bio_map[bio];
    if (bio_object == nullptr) {
      bio_object = std::make_shared<BioObject>();
    } else {
      assert(false && "find bio before queue");
    }
    // add bio but not with bvec
  }

  void processBioQueue2(unsigned long long bio,
                        struct bvec_array_info *bvec_info) {
    auto &bio_object = bio_map[bio];
    assert(bio_object != nullptr && "can not find bio object");
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
  }

  void processBioSplit(unsigned long long bio, unsigned long long parent_bio,
                       unsigned short bvec_idx_start,
                       unsigned short bvec_idx_end) {
    auto &parent_bio_object = bio_map[parent_bio];
    assert(parent_bio_object != nullptr && "can not find parent bio object");
    auto &child_bio_object = bio_map[bio];
    if (child_bio_object == nullptr) {
      child_bio_object = std::make_shared<BioObject>(); // update bio_map
    } else {
      assert(false && "find bio before split");
    }

    // add bio to relative request base on bvec_idx
    bvec_idx_end = bvec_idx_end >= parent_bio_object->associations.size()
                       ? parent_bio_object->associations.size() - 1
                       : bvec_idx_end;
    for (int i = bvec_idx_start; i <= bvec_idx_end; i++) {
      auto &association = parent_bio_object->associations[i];
      for (auto &request_object : association.relative_requests) {
        assert(request_object.expired() == false && "request not done yet");
        auto request = request_object.lock();
        auto io_request = std::dynamic_pointer_cast<IORequest>(request);
        io_request->addBioObject(child_bio_object);
      }
    }
  }

  void addEventToBio(unsigned long long bio, std::shared_ptr<SyncEvent> event) {
    auto &bio_object = bio_map[bio];
    assert(bio_object != nullptr && "can not find bio object");
    bio_object->addRelativeEvent(event);
  }

  void addEventToRequest(unsigned long long rq,
                         std::shared_ptr<SyncEvent> event) {
    auto &request_object = request_map[rq];
    assert(request_object != nullptr && "can not find request object");
    request_object->addEvent(event);
  }

  void addEventToRequestQueue(unsigned long long request_queue,
                              std::shared_ptr<SyncEvent> event) {
    auto &request_queue_object = request_queue_map[request_queue];
    assert(request_queue_object != nullptr &&
           "can not find request queue object");
    request_queue_object->addEvent(event);
  }

  void addUniqueEventToIORequest() {}

  struct RequestObject {
    std::vector<std::weak_ptr<BioObject>> bio_objects;
    void addEvent(std::shared_ptr<SyncEvent> event) {
      std::vector<int> rmIndex = {};
      for (int i = 0; i < bio_objects.size(); i++) {
        if (bio_objects[i].expired()) {
          rmIndex.push_back(i);
        } else {
          auto bio = bio_objects[i].lock();
          bio->addRelativeEvent(event);
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