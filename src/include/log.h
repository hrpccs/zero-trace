#include "basic_types.h"
#include "iotracer.h"
#include <bits/types/FILE.h>
#include <fstream>

double inline timestamp2ms(unsigned long long timestamp) {
  return timestamp / 1000000.0;
}

class FileLogHandler : public DoneRequestHandler {
public:
    FileLogHandler(const std::string& file_name){
        if(file_name.empty()){
            file = stdout;
            return;
        }
        file = fopen(file_name.c_str(), "w");
        if(!file){
            throw std::runtime_error("Can't open file " + file_name);
        }
    }

    FileLogHandler(FileLogHandler && other) : file(other.file){
        other.file = nullptr;
    }

    void setFile(FILE* file){
        if(this->file)
            fclose(this->file);
        this->file = file;
    }
    ~FileLogHandler(){
        if(file){
            fclose(file);
        }
    }

    virtual void HandleDoneRequest(std::shared_ptr<Request>, TraceConfig &) override;
    FILE* file;

    int skipped_requests = 0;
    int total_requests = 0;
    double estimated_avg_time = 0;
};