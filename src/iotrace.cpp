// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

#include "analyse.h"
#include "basic_event.h"
#include "event_defs.h"
#include "hook_point.h"
#include "io_analyse.h"
#include "iotrace.skel.h"
#include <argp.h>
#include <assert.h>
#include <bpf/libbpf.h>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <getopt.h>
#include <memory>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utility>

struct iotrace_bpf *skel;
pid_t curr_pid = 0;
FILE *output_file = NULL;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  /*
          this function is used to set to enable and redirect the output of
     bpf_trace_printk to stderr when LIBBPF_DEBUG is set
  */

  if (level == LIBBPF_DEBUG)
    return 0;
  return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig) {
  /*
          handling signal to stop iotrace process
  */
  exiting = true;
}
int once = 0;

static int handle_event(void *ctx, void *data, size_t data_sz) {
  if(data_sz == sizeof(bvec_array_info)){
    struct bvec_array_info* bvec_info = (struct bvec_array_info*)data;
    printf("bvec cnt %d\n",bvec_info->bvec_cnt);
    
  }
  struct event *e = (struct event *)data;
  if (e->pid == curr_pid || e->tid == curr_pid) {
    return 0;
  }
  const char *event_type_str = kernel_hook_type_str[e->event_type];
  const char *layer_type_str = info_type_str[e->info_type];
  return 0;
}

IOAnalyser *analyser;
unsigned long long Request::request_id = 0;

static int analyse(void *ctx, void *data, size_t data_sz) {
  analyser->AddTrace(data,data_sz);
  return 0;
}

void parse_args(int argc, char **argv) {
  /*
          Parse the arguments
  */
  long long opt;
  int pid = 0;
  int tid = 0;
  char *dev = NULL;
  char *cgroup = NULL;
  unsigned long long file = 0;
  unsigned long long directory = 0;
  char *output = NULL;
  std::string command;

  double time_threshold = 1.0;

  printf("Parsing arguments\n");
  output_file = stdout;

  while ((opt = getopt(argc, argv, "p:t:d:c:f:D:o:w:n:h")) != -1) {
    switch (opt) {
    case 'p':
      pid = atoi(optarg);
      skel->bss->target_tgid = pid;
      fprintf(output_file, "pid: %d\n", pid);
      break;
    case 't':
      tid = atoi(optarg);
      skel->bss->target_tid = tid;
      break;
    case 'd':
      dev = optarg;
      break;
    case 'c':
      cgroup = optarg;
      break;
    case 'f':
      file = atoi(optarg);
      skel->bss->target_file_inode = file;
      break;
    case 'D':
      directory = atoi(optarg);
      skel->bss->target_direrctory_inode = directory;
      break;
    case 'o':
      output = optarg;
      break;
    case 'w':
      time_threshold = atof(optarg);
      break;
    case 'n':
      command = std::string(optarg);
      std::strcpy(skel->bss->command, command.c_str());
      skel->bss->command_len = command.length();
      break;
    default:
      fprintf(stderr,
              "Usage: %s [-p pid] [-t tgid] [-d dev] [-c cgroup] [-f file] [-D "
              "directory] [-o output] [-t time threshold] [-n command to trace]\n",
              argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  std::filesystem::path output_path = std::filesystem::path();
  if (output != NULL) {
    output_path.assign(output);
  }
  std::filesystem::path dev_path = std::filesystem::path();
  if (dev != NULL) {
    dev_path.assign(dev);
  }

  TraceConfig config =
      TraceConfig(pid, tid, std::move(dev_path), file, directory,
                  time_threshold, std::move(output_path), std::move(command),skel);

  // Do something with the parsed arguments
  // #ifdef CONFIG_BLK_CGROUP
  // #endif
  auto handler = std::make_unique<IOEndHandler>(std::move(config));
  analyser = new IOAnalyser(std::move(handler));

  if (dev != NULL) {
    // get dev_t of the device
    struct stat st;
    if (stat(dev, &st) == -1) {
      fprintf(stderr, "Error getting dev_t of the device\n");
      exit(EXIT_FAILURE);
    }
    // set the dev_t in the bpf program
    skel->bss->target_dev = st.st_rdev;
  }

  if (cgroup != NULL) {
    // get the cgroup id
    assert(false && "not implemented yet");
  }
}

int main(int argc, char **argv) {

  // sudo mount -t debugfs none /sys/kernel/debug
  LIBBPF_OPTS(bpf_object_open_opts, open_opts);
  struct ring_buffer *rb = NULL;
  int err;
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Cleaner handling of Ctrl-C */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* Load and verify BPF application */
  open_opts.btf_custom_path = "/sys/kernel/btf/vmlinux";
  skel = iotrace_bpf::open(&open_opts);
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }
  printf("BPF skeleton loaded\n");

  // modify the bss section of the bpf program
  parse_args(argc, argv);

  /* Load & verify BPF programs */
  // err = iotrace_bpf__load(skel);
  err = iotrace_bpf::load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoints */
  err = iotrace_bpf::attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }
  /* Set up ring buffer polling */
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), analyse, NULL, NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }
  /* Process events */
  curr_pid = getpid();
  while (!exiting) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }

cleanup:
  /* Clean up */
  ring_buffer__free(rb);
  iotrace_bpf::destroy(skel);
  delete analyser;
  return err < 0 ? -err : 0;
}