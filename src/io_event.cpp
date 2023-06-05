#include "assert.h"
#include "basic_event.h"
#include "event_defs.h"
#include "hook_point.h"
#include <iostream>
#include <map>
#include <memory>
#include <unordered_map>
#include <utility>
#include "io_event.h"

bool IORequest::isPendingAsync() {
  Event *e = events.back().get();
  if (dynamic_cast<AsyncDuration *>(e)) {
    return true;
  }
  return false;
}

bool IORequest::isRelative(int pid,int tid,unsigned long long inode, unsigned long long offset,
                           unsigned long nr_bytes) {
  if(this->pid != pid || this->tid != tid){
    return false;
  }
  if(nr_bytes == 0){
    return true;
  }
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

bool IORequest::isEqual(unsigned long long inode, unsigned long long offset,
                        unsigned long nr_bytes) {
  if (this->inode != inode) {
    return false;
  }
  if (this->offset == offset && this->nr_bytes == nr_bytes) {
    return true;
  }
  return false;
}

void IORequest::addBioObject(std::shared_ptr<BioObject> bio) {
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

bool IORequest::AddBioObjectAndBuildMapping(std::shared_ptr<BioObject> bio,
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

// void print() override {}
void BlockPendingDuration::printfmtNtap(FILE *file, int tapnum,unsigned long long start) {
  for (int i = 0; i < relative_bio.size(); i++) {
    unsigned long long time = 0;
    auto bio = relative_bio[i];
    if(!bio->isDone){
      continue;
    }
    for (int j = 0; j < bio->relative_events.size(); j++) {
      auto event = bio->relative_events[j];
      for (int k = 0; k < tapnum; k++) {
        fprintf(file, "\t");
      }
      if (j == 0) {
        fprintf(file, " %s start bio op :%s %f ms", kernel_hook_type_str[event->event_type],bio->bio_op_str.c_str(),
                (event->timestamp - start) / 1000000.0);
      } else {
        fprintf(file, " %s time since start %f ms",
                kernel_hook_type_str[event->event_type],
                (event->timestamp - start) / 1000000.0);
      }
      time = event->timestamp;
      fprintf(file, "\n");
    }
  }
}

void BioObject::setBioOp(unsigned long bio_op) {
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

void BioObject::addAssociation(unsigned long long inode, unsigned long offset,
                               unsigned long nr_bytes) {
  associations.push_back(Association(inode, offset, nr_bytes));
}

void BioObject::isRelative(unsigned long long inode, unsigned long long offset,
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

void BioObject::updateBioStatus(std::shared_ptr<SyncEvent> event) {
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

void BioObject::addRelativeEvent(std::shared_ptr<SyncEvent> event) {
  if (isIssued) {
    if (event->event_type == block_unplug ||
        event->event_type == block_plug) {
      return;
    }
  }
  relative_events.push_back(event);
  updateBioStatus(event);
}
