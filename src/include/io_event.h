#pragma once

#include "assert.h"
#include "basic_event.h"
#include "event_defs.h"
#include "hook_point.h"
#include <iostream>
#include <map>
#include <memory>
#include <unordered_map>
#include <utility>

class BioObject : public AsyncObject {
public:
  BioObject() {
    isDone = false;
    isIssued = false;
  }
  BioObject(BioObject &other) {
    isDone = false;
    isIssued = false;
  }
  BioObject(BioObject &&other) {
    isDone = false;
    isIssued = false;
  }
  ~BioObject() {  }
  void print() { printf("BioObject\n"); }
  struct Association { // use to find
    Association(unsigned long long inode, unsigned long offset,
                unsigned long nr_bytes)
        : inode(inode), offset(offset), nr_bytes(nr_bytes) {}
    unsigned long long inode;
    unsigned long long offset;
    unsigned long long nr_bytes;
    std::vector<std::weak_ptr<Request>> relative_requests;
  };
  std::vector<Association> associations;
  std::shared_ptr<BioObject> parent;
  unsigned long bio_op;
  std::string bio_op_str;
  bool isDone;
  bool isIssued;
  enum req_opf {
    /* read sectors from the device */
    REQ_OP_READ = 0,
    /* write sectors to the device */
    REQ_OP_WRITE = 1,
    /* flush the volatile write cache */
    REQ_OP_FLUSH = 2,
    /* discard sectors */
    REQ_OP_DISCARD = 3,
    /* securely erase sectors */
    REQ_OP_SECURE_ERASE = 5,
    /* write the same sector many times */
    REQ_OP_WRITE_SAME = 7,
    /* write the zero filled sector many times */
    REQ_OP_WRITE_ZEROES = 9,
    /* Open a zone */
    REQ_OP_ZONE_OPEN = 10,
    /* Close a zone */
    REQ_OP_ZONE_CLOSE = 11,
    /* Transition a zone to full */
    REQ_OP_ZONE_FINISH = 12,
    /* write data at the current zone write pointer */
    REQ_OP_ZONE_APPEND = 13,
    /* reset a zone write pointer */
    REQ_OP_ZONE_RESET = 15,
    /* reset all the zone present on the device */
    REQ_OP_ZONE_RESET_ALL = 17,

    /* Driver private requests */
    REQ_OP_DRV_IN = 34,
    REQ_OP_DRV_OUT = 35,

    REQ_OP_LAST,
  };

  void setBioOp(unsigned long bio_op) {
    this->bio_op = bio_op;
    unsigned long op = bio_op;
    int i = 0;
    bio_op_str = std::string(10, ' ');
    if (op & (1<<18))
      bio_op_str[i++] = 'F';

    switch (op & ((1<<8)-1)) {
    case REQ_OP_WRITE:
    case REQ_OP_WRITE_SAME:
      bio_op_str[i++] = 'W';
      break;
    case REQ_OP_DISCARD:
      bio_op_str[i++] = 'D';
      break;
    case REQ_OP_SECURE_ERASE:
      bio_op_str[i++] = 'D';
      bio_op_str[i++] = 'E';
      break;
    case REQ_OP_FLUSH:
      bio_op_str[i++] = 'F';
      break;
    case REQ_OP_READ:
      bio_op_str[i++] = 'R';
      break;
    default:
      bio_op_str[i++] = 'N';
    }

    if (op & (1<<17))
      bio_op_str[i++] = 'F';
    if (op & (1<<19))
      bio_op_str[i++] = 'A';
    if (op & (1<<11))
      bio_op_str[i++] = 'S';
    if (op & (1<<12))
      bio_op_str[i++] = 'M';
  }

  void addAssociation(unsigned long long inode, unsigned long offset,
                      unsigned long nr_bytes) {
    associations.push_back(Association(inode, offset, nr_bytes));
  }

  void isRelative(unsigned long long inode, unsigned long long offset,
                  unsigned long nr_bytes, std::vector<int> &index) {
    for (int i = 0; i < associations.size(); i++) {
      auto &association = associations[i];
      // for (auto &association : associations) {
      if (association.inode == inode) {
        // [offset,offset+nr_bytes] has intersection with
        // [this->offset,this->offset+this->nr_bytes]
        if (std::max(offset, association.offset) <=
            std::min(offset + nr_bytes,
                     association.offset + association.nr_bytes)) {
          index.push_back(i);
        }
      } else {
        // printf("inode not match in bvec compare\n");
      }
    }
    return;
  }

  bool bioIsDone() { return isDone; }
  bool bioIsIssued() { return isIssued; }

  void updateBioStatus(std::shared_ptr<SyncEvent> event) {
    if (event->event_type == block_rq_complete) {
      isDone = true;
    }
    if (event->event_type == block_rq_issue) {
      isIssued = true;
    }
    if (event->event_type == rq_qos_requeue) {
      isIssued = false;
    }
  }
  void addRelativeEvent(std::shared_ptr<SyncEvent> event) override {
    if (isIssued) {
      if (event->event_type == block_unplug ||
          event->event_type == block_plug) {
        return;
      }
    }
    relative_events.push_back(event);
    updateBioStatus(event);
  }
};

class BlockPendingDuration : public AsyncDuration {
public:
  // void print() override {}
  void printfmtNtap(FILE *file, int tapnum) {
    for (int i = 0; i < relative_bio.size(); i++) {
      unsigned long long time = 0;
      auto bio = relative_bio[i];
      if(!bio->isDone){
        continue;
      }
      fprintf(file, "bio %d", i);
      for (int j = 0; j < bio->relative_events.size(); j++) {
        auto event = bio->relative_events[j];
        for (int k = 0; k < tapnum; k++) {
          fprintf(file, "\t");
        }
        if (j == 0) {
          fprintf(file, " %s start %s", kernel_hook_type_str[event->event_type],bio->bio_op_str.c_str());
        } else {
          fprintf(file, " %s time since last event %f ms",
                  kernel_hook_type_str[event->event_type],
                  (event->timestamp - time) / 1000000.0);
        }
        time = event->timestamp;
        fprintf(file, "\n");
      }
    }
  }
  // std::vector<std::shared_ptr<AsyncObject>> async_objects;
  std::vector<std::shared_ptr<BioObject>> relative_bio;
};

class IORequest : public Request {
public:
  IORequest(unsigned long pid, unsigned long tid, unsigned long long inode,
            unsigned long long dev, unsigned long offset,
            unsigned long nr_bytes)
      : pid(pid), tid(tid), inode(inode), dev(dev), offset(offset),
        nr_bytes(nr_bytes) {}
  bool isPendingAsync() {
    Event *e = events.back().get();
    if (dynamic_cast<AsyncDuration *>(e)) {
      return true;
    }
    return false;
  }

  bool isRelative(unsigned long long inode, unsigned long long offset,
                  unsigned long nr_bytes) {
    if (this->inode != inode) {
      return false;
    }
    // [offset,offset+nr_bytes] has intersection with
    // [this->offset,this->offset+this->nr_bytes]
    if (std::max(offset, this->offset) <=
        std::min(offset + nr_bytes, this->offset + this->nr_bytes)) {
      return true;
    }
    return false;
  }

  bool isEqual(unsigned long long inode, unsigned long long offset,
               unsigned long nr_bytes) {
    if (this->inode != inode) {
      return false;
    }
    if (this->offset == offset && this->nr_bytes == nr_bytes) {
      return true;
    }
    return false;
  }

  void addBioObject(std::shared_ptr<BioObject> bio) {
    if (!isPendingAsync()) {
      auto ad = std::make_unique<BlockPendingDuration>();
      Request::AddEvent(std::move(ad));
    }

    if (auto ad = dynamic_cast<BlockPendingDuration *>(events.back().get())) {
      // printf("add bio\n");
      ad->relative_bio.push_back(bio);
    } else {
      assert(false);
    }
  }

  bool AddBioObjectAndBuildMapping(std::shared_ptr<BioObject> bio,
                                   std::shared_ptr<IORequest> self) {
    std::vector<int> index;
    bio->isRelative(inode, offset, nr_bytes, index);
    if (index.empty()) {
      return false;
    }
    for (auto i : index) {
      bio->associations[i].relative_requests.push_back(self);
    }
    addBioObject(bio);
    return true;
  }

private:
  // identity
  unsigned long pid;
  unsigned long tid;
  unsigned long long inode;    // target file inode
  unsigned long long dev;      // target device
  unsigned long long offset;   // RW offset
  unsigned long long nr_bytes; // RW size
};
