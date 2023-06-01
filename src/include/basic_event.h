#pragma once

#include "event_defs.h"
#include "hook_point.h"
#include <iostream>
#include <memory>
#include <memory_resource>
#include <set>
#include <string>
#include <utility>
#include <vector>

class Event {
public:
  Event() {}
  virtual ~Event() {}
  // virtual void print() = 0;
  virtual void printfmt(FILE *) = 0;
  //   char comm[MAX_COMM_LEN];
};

class SyncEvent : public Event { // associated with one object
public:
  SyncEvent(kernel_hook_type type, unsigned long long timestamp,
            std::string comm)
      : comm(comm) {
    this->event_type = type;
    this->timestamp = timestamp;
  }
  ~SyncEvent() {}
  enum SyncEventType { ENTER, EXIT } type;
  enum kernel_hook_type event_type;
  std::string comm;
  unsigned long long timestamp;
  void printfmt(FILE *file) override {
    fprintf(file, "%s   comm: %s", kernel_hook_type_str[this->event_type],
            comm.c_str());
  }
};

class AsyncObject {
public:
  virtual void print() = 0;
  std::vector<std::shared_ptr<SyncEvent>> relative_events;
  void addRelativeEvent(std::shared_ptr<SyncEvent> event) {
    relative_events.push_back(event);
  }
};

class AsyncDuration
    : public Event { // associated with serveral async related objects
public:
  unsigned long long timestamp_start;
  unsigned long long timestamp_end;
  AsyncDuration() {}
  void setStartTime(unsigned long long timestamp) {
    timestamp_start = timestamp;
  }
  void setEndTime(unsigned long long timestamp) { timestamp_end = timestamp; }
  // void print() override { printf("AsyncEvent\n"); }
  void printfmt(FILE *file) override { fprintf(file, "AsyncEvent"); }
};
class Request {
  // a request is consisted of a series of syncronous events and several
  // asyncronous objects a request is identified by the first event a request is
  // ended by the last event
public:
  static unsigned long long request_id;
  Request() { id = this->request_id++; }
  virtual ~Request() {}
  void AddEvent(std::unique_ptr<Event> event) {
    events.push_back(std::move(event));
  }
  unsigned long long id;
  std::vector<std::unique_ptr<Event>> events;
};