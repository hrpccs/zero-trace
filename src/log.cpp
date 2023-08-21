#include "log.h"
#include "basic_types.h"
#include "hook_point.h"
#include "iotracer.h"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>

using std::fprintf;

//
void FileLogHandler::HandleDoneRequest(std::shared_ptr<Request> req,
                                       TraceConfig &config) {
  unsigned long long total_time = req->end_time - req->start_time;
  double ms = timestamp2ms(total_time);
  unsigned long long base_time = req->start_time;
  // time
  fprintf(file, "rq%lld  cost %.5lfms (tid pid) %d %d\t""ino %ld dir ino %ld dev 0x%lx\n", req->id, ms,
          req->syscall_tid, req->syscall_pid, req->syscall_inode,
          req->syscall_dir_inode, req->syscall_dev);
  fprintf(file,"avg : time - %.5lfms q2c - %.5lfms q2d - %.5lfms d2c - %.5lfms\n", ms,
          timestamp2ms(req->avg_q2c) / req->bio_cnt,
          timestamp2ms(req->avg_q2d) / req->bio_cnt,
          timestamp2ms(req->avg_d2c) / req->bio_cnt);
  fprintf(file, "avg : avg_readpage - %.5lfms avg_offcpu - %.5lfms avg_offcpu_ratio - %.5lf\n",
          timestamp2ms(req->avg_readpage) / req->done_count,
          timestamp2ms(req->avg_offcpu) / req->done_count,
         (double)req->avg_offcpu / req->avg_time);
  std::string indent = "";
  for (int i = 0; i < req->events.size(); i++) {
    double ems = timestamp2ms(req->events[i]->timestamp - base_time);
    const char *event_type = kernel_hook_type_str[req->events[i]->event_type];
    if (req->events[i]->trigger_type == trigger_type::ENTRY) {
      fprintf(file, "[%.5f]%s %s{\n", ems, indent.c_str(), event_type);
      indent += "  ";
    } else if (req->events[i]->trigger_type == trigger_type::EXIT) {
      indent = indent.substr(0, indent.size() - 2);
      fprintf(file, "[%.5f]%s } %s\n", ems, indent.c_str(), event_type);
    } else {
      fprintf(file, "[%.5f]%s %s\n", ems, indent.c_str(), event_type);
    }
  }
}

void GrafanaClientLogHandler::HandleDoneRequest(std::shared_ptr<Request> req,
                                                TraceConfig &config)
{
 while (req->spans.size() > 0)
    {
      req->spans.back()->End();
      req->spans.pop_back();
    }
  return;
}
