#pragma once

#include "basic_types.h"
#include "bpf/libbpf.h"
#include "event_defs.h"
#include "hook_point.h"
#include "iotrace.skel.h"
#include "mesgtype.h"
#include "qemu_uprobe.skel.h"
#include "utils.h"
#include "vsockutils.h"
#include <ctime>
#include <filesystem>
#include <memory>
#include <mutex>
#include <queue>
#include <random>
#include <semaphore.h>
#include <thread>
#include <unordered_map>

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
    virtio_enable = 1;
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
    printf("run as host: %d\n", asHost);
    printf("run as guest: %d\n", asGuest);
  }

  bool asHost;
  bool asGuest;

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
  RequestQueue() { sem_init(&sem, 0, 0); }
  ~RequestQueue() { sem_destroy(&sem); }
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

  ~IOTracer() {
    if (skel) {
      iotrace_bpf::destroy(skel);
    }
    if (rb) {
      bpf_map__unpin(skel->maps.ringbuffer, "/sys/fs/bpf/ringbuffer");
      ring_buffer__free(rb);
    }
    if (qemu_skel) {
      qemu_uprobe_bpf::destroy(qemu_skel);
    }
  }

  void Logger() {
    while (!exiting) {
      std::shared_ptr<Request> request;
      sem_wait(&request_to_log_queue.sem);
      {
        std::lock_guard<std::mutex> lock(request_to_log_queue.mutex);
        if (request_to_log_queue.results.empty()) {
          continue;
        }
        request = request_to_log_queue.results.front();
        request_to_log_queue.results.pop();
      }
      done_request_handler->HandleDoneRequest(request, config);
    }
  }

  bool findAndMergeQemuRq(std::shared_ptr<Request> &request) {
    long long offset = request->guest_offset_time;

    auto &bio_info = request->io_statistics;

    for (int i = 0; i < request->events.size(); i++) {
    }
  }

  void HostAgent() { // connect
    ServerEngine server;
    while (exiting) {
      Type type;
      void *data;
      server.recvMesg(type, data);
      if (type == TYPE_timestamps) {
        server.getDeltaHelper();
      } else if (type == TYPE_Request) {
        std::shared_ptr<Request> request =
            std::shared_ptr<Request>((Request *)data);
        // 把刚刚反序列化的 request 先保存着
        // 直接从 native_request_queue 里面取出来
      }
    }
  }

  void GuestAgent() { // connect
    ClientEngine client_engine;
    constexpr long long sync_timeout = 1e9 * 10; // 10s
    long long last_sync_time = 0;
    long long offset;
    while (!exiting) {
      std::shared_ptr<Request> request;
      sem_wait(&request_to_log_queue.sem);
      {
        long long curr = get_timestamp();
        if (curr - last_sync_time > sync_timeout) {
          offset = client_engine.getDelta();
          last_sync_time = curr;
        }
        std::lock_guard<std::mutex> lock(request_to_log_queue.mutex);
        request = request_to_log_queue.results.front();
        request_to_log_queue.results.pop();
        request->guest_offset_time = offset;
        int ret = client_engine.sendMesg(TYPE_Request, &request); // FIXME:
        fprintf(stdout, "send request to guest, len: %d\n", ret);
      }
    }
  }

  void AddEvent(void *data, size_t data_size);
  static int AddTrace(void *ctx, void *data, size_t data_size) {
    IOTracer *tracer = (IOTracer *)ctx;
    tracer->AddEvent(data, data_size);
    return 0;
  }

  void openBPF() {
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    int err;
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    open_opts.btf_custom_path = "/sys/kernel/btf/vmlinux";
    skel = iotrace_bpf::open(&open_opts);
    if (!skel) {
      fprintf(stderr, "Failed to open and load BPF skeleton\n");
      exit(1);
    }

    if (RUN_AS_HOST) {
      qemu_skel = qemu_uprobe_bpf::open(&open_opts);
      if (!qemu_skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        exit(1);
      }
    }
  }

  void configBPF() {
    if (config.asGuest && config.asHost) {
      fprintf(stderr, "can not run as guest and host at the same time\n");
      exit(1);
    }
    run_type = RUN_STANDALONE;
    config.qemu_enable = 0;
    if (config.asGuest) {
      run_type = RUN_AS_GUEST;
      config.virtio_enable = 1;
    }
    if (config.asHost) {
      run_type = RUN_AS_HOST;
      config.qemu_enable = 1;
      if (config.pid == 0) {
        fprintf(stderr, "qemu pid is not set\n");
        exit(1);
      }
    }
  }

  void loadAndAttachBPF() {
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
    err = iotrace_bpf::attach(skel);
    if (err) {
      fprintf(stderr, "Failed to attach BPF skeleton\n");
      exit(1);
    }
    if (RUN_AS_HOST) {
      err = qemu_uprobe_bpf::load(qemu_skel);
      if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        exit(1);
      }
      err = qemu_uprobe_bpf::attach(qemu_skel);
      if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        exit(1);
      }
    }
  }

  void setuptLogger() {
    std::thread t(&IOTracer::Logger, this);
    t.detach();
  }

  void startTracing(void *ctx) {
    int err;
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

  void stopTracing() { exiting = true; }

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
      unsigned int dev = e->virtio_layer_info.dev;
      fprintf(stdout,
              "event type: %s, trigger type: %d, rq_id: %d, sector: %lld, "
              "nr_bytes: %lld, dev: %u\n",
              kernel_hook_type_str[type], trigger, rq_id, 0, 0, dev);
    }
    // const char *event_type_str = kernel_hook_type_str[e->event_type];
    // const char *layer_type_str = info_type_str[e->info_type];
    // fprintf(stdout,"event type: %s, layer type: %s\n", event_type_str,
    // layer_type_str);
    return 0;
  }

  void HandleDoneRequest(std::shared_ptr<Request> req) {
    if (run_type == RUN_AS_HOST) {
      std::lock_guard<std::mutex> lock(native_request_queue.mutex);
      native_request_queue.results.push(req);
      auto& ioinfo = req->io_statistics;
      for(int i = 0; i < ioinfo.size(); i++) {
        fprintf(stdout,"isVirtIO %d offset %lld nr_bytes %lld\n", ioinfo[i].isVirtIO, ioinfo[i].offset, ioinfo[i].nr_bytes);
      }
    } else {
      unsigned long long total_time = req->end_time - req->start_time;
      double ms = total_time / 1000000.0;
      if (ms < config.time_threshold) {
        std::lock_guard<std::mutex> lock(request_to_log_queue.mutex);
        request_to_log_queue.results.push(req);
        sem_post(&request_to_log_queue.sem);
        return;
      }
    }

  }

  void HandleBlockEvent(struct event *data);
  void HandleFsEvent(struct event *data);
  void HandleSyscallEvent(struct event *data);
  void HandleSchedEvent(struct event *data);
  void HandleScsiEvent(struct event *data);
  void HandleNvmeEvent(struct event *data);
  void HandleVirtioEvent(struct event *data);
  void HandleQemuEvent(struct event *data);
  enum RunType { RUN_AS_GUEST, RUN_AS_HOST, RUN_STANDALONE };
  RunType run_type = RUN_STANDALONE;
  bool exiting;
  struct iotrace_bpf *skel;
  struct qemu_uprobe_bpf *qemu_skel;
  struct ring_buffer *rb;
  TraceConfig config;
  std::unique_ptr<DoneRequestHandler> done_request_handler;
  RequestQueue request_to_log_queue;
  RequestQueue native_request_queue;
  std::unordered_map<int, std::shared_ptr<Request>> requests;
  std::unordered_map<int, std::shared_ptr<Request>> bio_requests;
  std::unordered_map<int, std::shared_ptr<Request>> rq_requests;
  std::unordered_map<int, std::shared_ptr<Request>> qemu_tid_requests;
  long long setup_timestamp = 0;
};