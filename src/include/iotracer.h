#pragma once

#include "basic_types.h"
#include "bpf/libbpf.h"
#include "event_defs.h"
#include "hook_point.h"
#include "iotrace.skel.h"
#include "qemu_uprobe.skel.h"
#include "utils.h"
#include <ctime>
#include <filesystem>
#include <memory>
#include <queue>
#include <thread>
#include <unordered_map>
#include <queue>
#include <semaphore.h>

struct TraceConfig {
  TraceConfig() {
    qemu_enable = 0;
    syscall_enable = 1;
    vfs_enable = 1;
    block_enable = 1;
    scsi_enable = 1;
    nvme_enable = 1;
    filemap_enable = 0;
    iomap_enable = 1;
    sched_enable = 1;
    virtio_enable = 0;
    task_name = "";
    pid = 0;
    tid = 0;
    file_path = "";
    directory_path = "";
    device_path = "";
    cgroup_path = "";
    time_threshold = 10;
    timer_trigger_duration = 0;
  }

  TraceConfig(TraceConfig &&config) {
    qemu_enable = config.qemu_enable;
    syscall_enable = config.syscall_enable;
    vfs_enable = config.vfs_enable;
    block_enable = config.block_enable;
    scsi_enable = config.scsi_enable;
    nvme_enable = config.nvme_enable;
    filemap_enable = config.filemap_enable;
    iomap_enable = config.iomap_enable;
    sched_enable = config.sched_enable;
    virtio_enable = config.virtio_enable;
    task_name = std::move(config.task_name);
    pid = config.pid;
    tid = config.tid;
    file_path = std::move(config.file_path);
    directory_path = std::move(config.directory_path);
    device_path = std::move(config.device_path);
    cgroup_path = std::move(config.cgroup_path);
    time_threshold = config.time_threshold;
    timer_trigger_duration = config.timer_trigger_duration;
  }

  void getFilterConfig(struct filter_config *config) {
    config->tgid = pid;
    config->tid = tid;
    for (int i = 0; i < task_name.size(); i++) {
      config->command[i] = task_name[i];
    }
    config->command_len = task_name.size();
    if (task_name.size() > 0) {
      config->filter_by_command = 1;
    }

    config->cgroup_id = 0;
    config->dev = 0;
    config->directory_inode = 0;
    config->inode = 0;


    if (cgroup_path.size() > 0) {
      config->cgroup_id = get_cgroup_id(cgroup_path.c_str());
    }
    if (device_path.size() > 0) {
      config->dev = get_device_id(device_path.c_str());
    }
    if (file_path.size() > 0) {
      config->inode = get_file_inode(file_path.c_str());
    }
    if (directory_path.size() > 0) {
      config->directory_inode = get_file_inode(directory_path.c_str());
    }

    printf("filter config: tgid: %d, tid: %d, command: %s, cgroup_id: %lld, "
           "dev: %ld, inode: %lld, directory_inode: %lld\n",
           config->tgid, config->tid, config->command, config->cgroup_id,
           config->dev, config->inode, config->directory_inode);
    printf("file path: %s\n", file_path.c_str());
    printf("directory path: %s\n", directory_path.c_str());
    printf("device path: %s\n", device_path.c_str());
    printf("cgroup path: %s\n", cgroup_path.c_str());
  }

  // ebpf skel
  // trace enble
  bool qemu_enable = 0;
  bool syscall_enable = 1;
  bool vfs_enable = 1;
  bool block_enable = 1;
  bool scsi_enable = 1;
  bool nvme_enable = 1;
  bool filemap_enable = 0;
  bool iomap_enable = 1;
  bool sched_enable = 1;
  bool virtio_enable = 0;

  // filter
  std::string task_name;
  int pid = 0;
  int tid = 0;
  std::string file_path;
  std::string directory_path;
  std::string device_path;
  std::string cgroup_path;

  // handler
  double time_threshold;      // ms
  int timer_trigger_duration; // s
};

class DoneRequestHandler {
public:
  explicit DoneRequestHandler() {}
  virtual ~DoneRequestHandler() {}
  virtual void HandleDoneRequest(std::shared_ptr<Request>, TraceConfig &) = 0;
};

struct RequestQueue {
  // 信号量
  RequestQueue() {
    sem_init(&sem, 0, 0);
  }
  ~RequestQueue() {
    sem_destroy(&sem);
  }
  sem_t sem;
  std::mutex mutex;
  std::queue<std::shared_ptr<Request>> results;
};

class IOTracer {
public:
  IOTracer(std::unique_ptr<DoneRequestHandler> handler)
      : done_request_handler(std::move(handler)), config() {
    exiting = false;
  }

  IOTracer(std::unique_ptr<DoneRequestHandler> handler, TraceConfig &&config)
      : done_request_handler(std::move(handler)), config(std::move(config)) {
    exiting = false;
  }

  virtual ~IOTracer() {
    if (skel) {
      iotrace_bpf::destroy(skel);
    }
    if (rb) {
      bpf_map__unpin(skel->maps.ringbuffer,"/sys/fs/bpf/ringbuffer");
      ring_buffer__free(rb);
    }
  }

  virtual void coworker() {
    while (!exiting) {
      std::shared_ptr<Request> request;
      sem_wait(&done_request_queue.sem);
      {
        std::lock_guard<std::mutex> lock(done_request_queue.mutex);
        if (done_request_queue.results.empty()) {
          continue;
        }
        request = done_request_queue.results.front();
        done_request_queue.results.pop();
      }
      done_request_handler->HandleDoneRequest(request, config);
    }
  }

  virtual void AddEvent(void *data, size_t data_size);
  static int AddTrace(void *ctx, void *data, size_t data_size) {
    IOTracer *tracer = (IOTracer *)ctx;
    tracer->AddEvent(data, data_size);
    return 0;
  }

  virtual void openBPF() {
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    int err;
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    open_opts.btf_custom_path = "/sys/kernel/btf/vmlinux";
    skel = iotrace_bpf::open(&open_opts);
    if (!skel) {
      fprintf(stderr, "Failed to open and load BPF skeleton\n");
      exit(1);
    }
  }

  virtual void configAndLoadBPF() {
    config.qemu_enable = 0; // 默認不開始 qemu
    skel->bss->qemu_enable = config.qemu_enable;
    skel->bss->syscall_enable = config.syscall_enable;
    skel->bss->vfs_enable = config.vfs_enable;
    skel->bss->block_enable = config.block_enable;
    skel->bss->scsi_enable = config.scsi_enable;
    skel->bss->nvme_enable = config.nvme_enable;
    skel->bss->filemap_enable = config.filemap_enable;
    skel->bss->iomap_enable = config.iomap_enable;
    skel->bss->sched_enable = config.sched_enable;
    skel->bss->virtio_enable = config.virtio_enable;
    config.getFilterConfig(&skel->bss->filter_config);
    int err = iotrace_bpf::load(skel);
    if (err) {
      fprintf(stderr, "Failed to load and verify BPF skeleton\n");
      exit(1);
    }
  }

  virtual void startCoworker() {
    std::thread t(&IOTracer::coworker, this);
    t.detach();
  }

  virtual void startTracing(void *ctx) {
    int err;
    err = iotrace_bpf::attach(skel);
    if (err) {
      fprintf(stderr, "Failed to attach BPF skeleton\n");
      exit(1);
    }
    setup_timestamp = get_timestamp();
    int rb_fd = bpf_map__fd(skel->maps.ringbuffer);
    rb = ring_buffer__new(rb_fd, IOTracer::AddTrace, ctx, nullptr);
    if (!rb) {
      fprintf(stderr, "Failed to create ring buffer\n");
      exit(1);
    }
    while (!exiting) {
      err = ring_buffer__poll(rb, 100);
      if (err < 0) {
        fprintf(stderr, "Failed to consume ring buffer\n");
        exit(1);
      }
    }
  }

  int static debug(void *ctx, void *data, size_t data_size) {
    struct event *e = (struct event *)data;
    if (e->info_type == qemu_layer) {
      int type = e->event_type;
      int trigger = e->trigger_type;
      int tid = e->qemu_layer_info.tid;
      int async_task_id = e->qemu_layer_info.prev_tid;
      long long offset = e->qemu_layer_info.offset;
      long long nr_bytes = e->qemu_layer_info.nr_bytes;
      long long rqaddr = e->qemu_layer_info.virt_rq_addr;
      // fprintf(stdout,"event type: %s, trigger type: %d, offset: %lld,
      // nr_bytes: %lld, rqaddr: %lld\n", kernel_hook_type_str[type], trigger,
      // offset, nr_bytes, rqaddr);
      fprintf(stdout,
              "event type: %s, trigger type: %d, offset: %lld, nr_bytes: %lld, "
              "rqaddr: %lld, tid: %d, async_task_id: %d\n",
              kernel_hook_type_str[type], trigger, offset, nr_bytes, rqaddr,
              tid, async_task_id);
    } else if (e->info_type == syscall_layer) {
      int type = e->event_type;
      int trigger = e->trigger_type;
      int tid = e->syscall_layer_info.tid;
      int tgid = e->syscall_layer_info.tgid;
      int fd = e->syscall_layer_info.fd;
      int inode = e->syscall_layer_info.inode;
      int dir_inode = e->syscall_layer_info.dir_inode;
      int dev = e->syscall_layer_info.dev;

      fprintf(stdout,
              "event type: %s, trigger type: %d, tid: %d, tgid: %d, fd: %d, "
              "inode: %d, dir_inode: %d, dev: %d\n",
              kernel_hook_type_str[type], trigger, tid, tgid, fd, inode,
              dir_inode, dev);
    } else if (e->info_type == fs_layer) {
      int type = e->event_type;
      int trigger = e->trigger_type;
      int tid = e->fs_layer_info.tid;
      int tgid = e->fs_layer_info.tgid;
      unsigned long offset = e->fs_layer_info.offset;
      unsigned long nr_bytes = e->fs_layer_info.bytes;

      fprintf(stdout,
              "event type: %s, trigger type: %d, tid: %d, tgid: %d, offset: "
              "%lu, nr_bytes: %lu\n",
              kernel_hook_type_str[type], trigger, tid, tgid, offset, nr_bytes);
    } else if (e->info_type == sched_layer) {
      int prev_tid = e->sched_layer_info.prev_tid;
      int next_tid = e->sched_layer_info.next_tid;
      int type = e->event_type;
      int trigger = e->trigger_type;
      fprintf(stdout,
              "event type: %s, trigger type: %d, prev_tid: %d, next_tid: %d\n",
              kernel_hook_type_str[type], trigger, prev_tid, next_tid);
    } else if (e->info_type == block_layer) {
      int type = e->event_type;
      int trigger = e->trigger_type;
      int tid = e->block_layer_info.tid;
      int tgid = e->block_layer_info.tgid;
      long long offset = e->block_layer_info.approximate_filemap_start_offset;
      long long len = e->block_layer_info.approximate_filemap_len;
      fprintf(stdout,
              "event type: %s, trigger type: %d, tid: %d, tgid: %d, offset: "
              "%lld, len: %lld\n",
              kernel_hook_type_str[type], trigger, tid, tgid, offset, len);
    } else if (e->info_type == nvme_layer) {
      int type = e->event_type;
      int trigger = e->trigger_type;
      int rq_id = e->nvme_layer_info.rq_id;
      fprintf(stdout, "event type: %s, trigger type: %d, rq_id: %d\n",
              kernel_hook_type_str[type], trigger, rq_id);
    } else if (e->info_type == scsi_layer) {
      int type = e->event_type;
      int trigger = e->trigger_type;
      int rq_id = e->scsi_layer_info.rq_id;
      fprintf(stdout, "event type: %s, trigger type: %d, rq_id: %d\n",
              kernel_hook_type_str[type], trigger, rq_id);
    } else if (e->info_type == virtio_layer) {
      int type = e->event_type;
      int trigger = e->trigger_type;
      int rq_id = e->virtio_layer_info.rq_id;
      long long sector = e->virtio_layer_info.sector;
      long long nr_bytes = e->virtio_layer_info.nr_bytes;
      unsigned int dev = e->virtio_layer_info.dev;
      fprintf(stdout,
              "event type: %s, trigger type: %d, rq_id: %d, sector: %lld, "
              "nr_bytes: %lld, dev: %u\n",
              kernel_hook_type_str[type], trigger, rq_id, sector, nr_bytes,
              dev);
    }
    // const char *event_type_str = kernel_hook_type_str[e->event_type];
    // const char *layer_type_str = info_type_str[e->info_type];
    // fprintf(stdout,"event type: %s, layer type: %s\n", event_type_str,
    // layer_type_str);
    return 0;
  }

  void startDebug() {
    int err;
    err = iotrace_bpf::attach(skel);
    if (err) {
      fprintf(stderr, "Failed to attach BPF skeleton\n");
      exit(1);
    }
    setup_timestamp = get_timestamp();
    int rb_fd = bpf_map__fd(skel->maps.ringbuffer);
    rb = ring_buffer__new(rb_fd, IOTracer::debug, nullptr, nullptr);
    if (!rb) {
      fprintf(stderr, "Failed to create ring buffer\n");
      exit(1);
    }
    while (!exiting) {
      err = ring_buffer__poll(rb, 100);
      if (err < 0) {
        fprintf(stderr, "Failed to consume ring buffer\n");
        exit(1);
      }
    }
  }

  virtual void HandleDoneRequest(std::shared_ptr<Request> req) {
  unsigned long long total_time = req->end_time - req->start_time;
  double ms = total_time / 1000000.0;
  if (ms < config.time_threshold) {
    return;
  }
    std::lock_guard<std::mutex> lock(done_request_queue.mutex);
    done_request_queue.results.push(req);
    sem_post(&done_request_queue.sem);
  }

  std::shared_ptr<Request> GetRequestByTid(int tid) {
    if (requests.find(tid) != requests.end()) {
      return requests[tid];
    } else {
      return nullptr;
    }
  }
  std::shared_ptr<Request> GetRequestByBioid(int bio_id) {
    if (bio_requests.find(bio_id) != bio_requests.end()) {
      return bio_requests[bio_id];
    } else {
      return nullptr;
    }
  }
  std::shared_ptr<Request> GetRequestByRqid(int rq_id) {
    if (rq_requests.find(rq_id) != rq_requests.end()) {
      return rq_requests[rq_id];
    } else {
      return nullptr;
    }
  }

  void stopTracing() { exiting = true; }


  void HandleBlockEvent(struct event *data);
 

  bool exiting;
  struct iotrace_bpf *skel;
  struct ring_buffer *rb;
  TraceConfig config;
  std::unique_ptr<DoneRequestHandler> done_request_handler;
  RequestQueue done_request_queue;
  std::unordered_map<int, std::shared_ptr<Request>> requests;
  std::unordered_map<int, std::shared_ptr<Request>> bio_requests;
  std::unordered_map<int, std::shared_ptr<Request>> rq_requests;
  long long setup_timestamp = 0;
};