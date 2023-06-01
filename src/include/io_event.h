#pragma once

#include "assert.h"
#include "basic_event.h"
#include "event_defs.h"
#include <iostream>
#include <map>
#include <memory>
#include <unordered_map>
#include <utility>

class BioObject : public AsyncObject {
public:
  BioObject() { printf("Create BioObject\n"); }
  BioObject(BioObject &other) { printf("Copy BioObject\n"); }
  BioObject(BioObject &&other) { printf("Move BioObject\n"); }
  ~BioObject() { printf("Delete BioObject\n"); }
  void print() { printf("BioObject\n"); }
  struct Association { // use to find
    unsigned long long inode;
    unsigned long offset;
    unsigned long nr_bytes;
  };
};

class BlockPendingDuration : public AsyncDuration {
public:
  // void print() override {}

  void printfmtNtap(FILE *file, int tapnum) {
    int j = 0;
    for (auto ptr : relative_bio) {
      j++;
      for (auto syncevent : ptr->relative_events) {
        for (int i = 0; i < tapnum; i++) {
          fprintf(file, "\t");
        }
        fprintf(file, "bio %d", j);
        syncevent->printfmt(file);
      }
      fprintf(file, "\n");
    }
  }
  // std::vector<std::shared_ptr<AsyncObject>> async_objects;
  std::set<std::shared_ptr<BioObject>> relative_bio;
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

  void addBioObject(std::shared_ptr<BioObject> bio) {
    if (!isPendingAsync()) {
      auto ad = std::make_unique<BlockPendingDuration>();
      Request::AddEvent(std::move(ad));
    }
    if (auto ad = dynamic_cast<BlockPendingDuration *>(events.back().get())) {
      printf("add bio\n");
      ad->relative_bio.insert(bio);
    } else {
      assert(false);
    }
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
