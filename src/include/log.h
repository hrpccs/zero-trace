#include "basic_types.h"
#include "iotracer.h"
#include <bits/types/FILE.h>
#include <fstream>

double inline timestamp2ms(unsigned long long timestamp) {
    return timestamp / 1000000.0;
}

class FileLogHandler : public DoneRequestHandler {
  public:
    FileLogHandler(const std::string& file_name) {
        if (file_name.empty()) {
            file = stdout;
            return;
        }
        file = fopen(file_name.c_str(), "w");
        if (!file) {
            throw std::runtime_error("Can't open file " + file_name);
        }
    }

    FileLogHandler(FileLogHandler&& other) : file(other.file) {
        other.file = nullptr;
    }

    void setFile(FILE* file) {
        if (this->file)
            fclose(this->file);
        this->file = file;
    }
    ~FileLogHandler() {
        if (file) {
            fclose(file);
        }
    }

    //   void analyseRequest(std::shared_ptr<Request> req,FILE* file,long long*
    //   offcpu_time,long long* avg_time_getpage,long long* getpage_start,long
    //   long* getpage_count,long long* q2c_time,long long* q2d_time,long long*
    //   d2c_time){
    virtual void HandleDoneRequest(std::shared_ptr<Request>,
                                   TraceConfig&) override;
    FILE* file;
};

#include "otlp.h"

class GrafanaClientLogHandler : public DoneRequestHandler {
  public:
    GrafanaClientLogHandler(const std::string& file_name) {
        InitTracer();
    }

    ~GrafanaClientLogHandler() {
        CleanupTracer();
    }

    virtual void HandleDoneRequest(std::shared_ptr<Request>,
                                   TraceConfig&) override;

    int sockfd;
    struct sockaddr_in server_addr;

    int skipped_requests = 0;
    int total_requests = 0;
    double estimated_avg_time = 0;
};