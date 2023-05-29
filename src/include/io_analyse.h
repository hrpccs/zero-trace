#pragma once

#include "analyse.h"
#include "basic_event.h"
#include "cstdio"
#include "event_defs.h"
#include "hook_point.h"
#include "io_event.h"
#include <cstdio>
#include <map>
#include <memory>
#include <utility>
#include <vector>



class IOEndHandler : public DoneRequestHandler {
public:
  IOEndHandler(TraceConfig config): DoneRequestHandler(std::move(config)) {
    std::filesystem::path& output_path = config.output_path;
    if (!output_path.empty()) {
      outputFile = fopen(output_path.c_str(), "w");
    } else {
      outputFile = stdout;
    }
  }

  ~IOEndHandler() {
    if (outputFile != stdout) {
      fclose(outputFile);
    }
  }
  void HandleDoneRequest(std::unique_ptr<Request>) override;
  FILE *outputFile;
};

class IOAnalyser : public Analyser {
public:
  IOAnalyser(std::unique_ptr<DoneRequestHandler> handler) : Analyser(std::move(handler)) {}
  ~IOAnalyser() {}
  void AddTrace(struct event *e) override;
  void AddRequest(std::unique_ptr<IORequest> request) {
    pending_requests.push_back(std::move(request));
  }
  void EndRequest(int idx) {
    std::unique_ptr<IORequest> request = std::move(pending_requests[idx]);
    pending_requests.erase(pending_requests.begin() + idx);
    Analyser::DoneRequest(std::move(request));
  }

  std::vector<std::unique_ptr<IORequest>> pending_requests;
  std::map<unsigned long long, std::shared_ptr<BioObject>> bio_map;

  // statics
  unsigned long long trace_count = 0;
  unsigned long long trace_unhandle = 0;
};