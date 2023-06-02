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
    Association(unsigned long long inode, unsigned long offset,
                unsigned long nr_bytes)
        : inode(inode), offset(offset), nr_bytes(nr_bytes) {}
    unsigned long long inode;
    unsigned long long offset;
    unsigned long long nr_bytes;
    std::vector<std::weak_ptr<Request>> relative_requests;
  };
  std::vector<Association> associations;

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
        printf("inode not match in bvec compare\n");
      }
    }
    return;
  }
  
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
      ad->relative_bio.insert(bio);
    } else {
      assert(false);
    }
  }

  bool AddBioObjectAndBuildMapping(std::shared_ptr<BioObject> bio,std::shared_ptr<IORequest> self) {
    std::vector<int> index;
    bio->isRelative(inode, offset, nr_bytes, index);
    if(index.empty()){
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
