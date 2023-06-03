#pragma once

#include "basic_event.h"
#include "event_defs.h"
#include "io_event.h"
#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

struct TraceConfig {

  TraceConfig(const TraceConfig &) = default;
  TraceConfig(TraceConfig &&) = default;
  TraceConfig &operator=(const TraceConfig &) = default;
  TraceConfig &operator=(TraceConfig &&) = default;
  TraceConfig(unsigned long pid, unsigned long tid, std::filesystem::path dev,
              unsigned long ino, unsigned long long dir_ino,
              double time_threshold, std::filesystem::path output_path,std::string command)
      : pid(pid), tid(tid), dev(std::move(dev)), ino(ino), dir_ino(dir_ino),
        time_threshold(time_threshold), output_path(std::move(output_path)), command(std::move(command)) {}
  // trace target
  unsigned long pid;
  unsigned long tid;
  std::filesystem::path dev;
  unsigned long ino;
  unsigned long long dir_ino;
  std::string command;

  // trigger threshold
  double time_threshold;
  // trace result output
  std::filesystem::path output_path;

  std::string toString() {
    std::string str = "pid: " + std::to_string(pid) + "\n";
    str += "tid: " + std::to_string(tid) + "\n";
    str += "dev: " + dev.string() + "\n";
    str += "ino: " + std::to_string(ino) + "\n";
    str += "dir_ino: " + std::to_string(dir_ino) + "\n";
    str += "time_threshold: " + std::to_string(time_threshold) + "ms\n";
    str += "output_path: " + output_path.string() + "\n";
    return str;
  }
};

class DoneRequestHandler {
public:
  explicit DoneRequestHandler(TraceConfig&& config) : config(std::move(config)) {}
  virtual void HandleDoneRequest(std::shared_ptr<Request>) = 0;
  //
  TraceConfig config;
};

class Analyser {
public:
  Analyser(std::unique_ptr<DoneRequestHandler> handler) {
    this->SetDoneRequestHandler(std::move(handler));
  }
  ~Analyser() {}
  virtual void AddTrace(void *data,size_t data_size) = 0;
  void DoneRequest(std::shared_ptr<Request> req) {
    done_request_handler->HandleDoneRequest(req);
  }

private:
  void SetDoneRequestHandler(std::unique_ptr<DoneRequestHandler> handler) {
    done_request_handler = std::move(handler);
  }
  std::unique_ptr<DoneRequestHandler> done_request_handler;
};