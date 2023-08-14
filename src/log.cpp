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

  // assign req value to request
  ProtoRequest request;
  std::cout << "emit request"
            << "\n";
  request.set_proto_request_duration(req->end_time - req->start_time);
  unsigned long long base_time = req->start_time;

  for (int i = 0; i < req->events.size(); i++)
  {
    ProtoEvent event;
    double ems = timestamp2ms(req->events[i]->timestamp - base_time);
    event.set_proto_event_duration(ems);
    event.set_proto_event_id(req->events[i]->timestamp); // time stamp is unique

    const char *event_type = kernel_hook_type_str[req->events[i]->event_type];
    if (req->events[i]->trigger_type == trigger_type::ENTRY)
    {
      event.set_proto_trigger_type(ProtoTriggerType::proto_trigger_entry);
    }
    else if (req->events[i]->trigger_type == trigger_type::EXIT)
    {
      event.set_proto_trigger_type(ProtoTriggerType::proto_trigger_exit);
    }
    else
    {
      event.set_proto_trigger_type(ProtoTriggerType::proto_trigger_normal);
    }

    request.add_proto_events()->CopyFrom(event);
  }

  std::string serialized_request;
  request.SerializeToString(&serialized_request);

  ssize_t bytes_sent = sendto(sockfd, serialized_request.c_str(), serialized_request.length(), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));

  if (bytes_sent < 0)
  {
    perror("Error sending data");
  }
}
