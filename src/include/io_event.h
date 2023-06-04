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

  void setBioOp(unsigned long bio_op);

  void addAssociation(unsigned long long inode, unsigned long offset,
                      unsigned long nr_bytes);

  void isRelative(unsigned long long inode, unsigned long long offset,
                  unsigned long nr_bytes, std::vector<int> &index);

  bool bioIsDone() { return isDone; }
  bool bioIsIssued() { return isIssued; }

  void updateBioStatus(std::shared_ptr<SyncEvent> event);
  void addRelativeEvent(std::shared_ptr<SyncEvent> event) override;
};

class BlockPendingDuration : public AsyncDuration {
public:
  void printfmtNtap(FILE *file, int tapnum);
  // std::vector<std::shared_ptr<AsyncObject>> async_objects;
  std::vector<std::shared_ptr<BioObject>> relative_bio;
};

class IORequest : public Request {
public:
  IORequest(unsigned long pid, unsigned long tid, unsigned long long inode,
            unsigned long long dev, unsigned long offset,
            unsigned long nr_bytes, std::string comm)
      : pid(pid), tid(tid), inode(inode), dev(dev), offset(offset),
        nr_bytes(nr_bytes) ,comm(comm){}
  bool isPendingAsync();

  bool isRelative(unsigned long long inode, unsigned long long offset,
                  unsigned long nr_bytes);

  bool isEqual(unsigned long long inode, unsigned long long offset,
               unsigned long nr_bytes);

  void addBioObject(std::shared_ptr<BioObject> bio);

  bool AddBioObjectAndBuildMapping(std::shared_ptr<BioObject> bio,
                                   std::shared_ptr<IORequest> self);

  // identity
  unsigned long pid;
  unsigned long tid;
  unsigned long long inode;    // target file inode
  unsigned long long dev;      // target device
  unsigned long long offset;   // RW offset
  unsigned long long nr_bytes; // RW size
  std::string comm;
};
