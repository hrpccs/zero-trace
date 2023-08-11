#include "log.h"
#include "basic_types.h"
#include "hook_point.h"
#include "kernel_tracer.h"
#include <fstream>
#include <iostream>
#include <memory>

using std::fprintf;

//
void FileLogHandler::HandleDoneRequest(std::shared_ptr<Request> req,
                                       TraceConfig &config) {
  unsigned long long total_time = req->end_time - req->start_time;
  double ms = timestamp2ms(total_time);
  estimated_avg_time = 0.9 * estimated_avg_time + 0.1 * ms;
  if (ms < config.time_threshold) {
    this->total_requests++;
  }
  unsigned long long base_time = req->start_time;
  // print out basic info
  // time
  fprintf(file, "rq%lld [%d:%d::%d] cost %.5lfms (tid pid) %d %d\n", req->id,
          req->start_tm.tm_hour, req->start_tm.tm_min, req->start_tm.tm_sec, ms,
          req->syscall_tid, req->syscall_pid);
  std::string indent = "";
  for (int i = 0; i < req->events.size(); i++) {
    double ems = timestamp2ms(req->events[i]->timestamp - base_time);
    const char *event_type = kernel_hook_type_str[req->events[i]->event_type];
    if (req->events[i]->trigger_type == trigger_type::ENTRY) {
      fprintf(file, "[%.5f]%s %s{\n", ems, indent.c_str(), event_type);
      indent += "  ";
    } else if (req->events[i]->trigger_type == trigger_type::EXIT) {
      indent = indent.substr(0, indent.size() - 2);
      fprintf(file, "[%.5f]%s } %s\n", ems, indent.c_str(),event_type);
    } else {
        fprintf(file, "[%.5f]%s %s\n", ems, indent.c_str(), event_type);
    }
  }
}