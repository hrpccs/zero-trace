#pragma once

#define KERNEL_HOOK_TYPE_DEF(X)                                                \
  X(qemu__virtio_blk_handle_request)                                           \
  X(qemu__virtio_blk_req_complete)                                             \
  X(qemu__blk_aio_pwritev)                                                     \
  X(qemu__blk_aio_preadv)                                                      \
  X(qemu__blk_aio_flush)                                                       \
  X(qemu__qcow2_co_pwritev_part)                                               \
  X(qemu__qcow2_co_preadv_part)                                                \
  X(qemu__qcow2_co_flush_to_os)                                                \
  X(qemu__raw_co_prw)                                                          \
  X(qemu__raw_co_flush_to_disk)                                                \
  X(qemu__handle_aiocb_rw)                                                     \
  X(qemu__handle_aiocb_flush)                                                  \
  X(syscall__read)                                                             \
  X(syscall__write)                                                            \
  X(syscall__pread64)                                                          \
  X(syscall__pwrite64)                                                         \
  X(syscall__readv)                                                            \
  X(syscall__writev)                                                           \
  X(syscall__preadv)                                                           \
  X(syscall__pwritev)                                                          \
  X(syscall__fsync)                                                            \
  X(syscall__fdatasync)                                                        \
  X(fs__do_iter_read)                                                          \
  X(fs__do_iter_write)                                                         \
  X(fs__vfs_iocb_iter_write)                                                   \
  X(fs__vfs_iocb_iter_read)                                                    \
  X(fs__vfs_read)                                                              \
  X(fs__vfs_write)                                                             \
  X(fs__vfs_fsync_range)                                                       \
  X(fs__generic_file_read_iter)                                                \
  X(fs__generic_file_write_iter)                                               \
  X(fs__filemap_get_pages)                                                     \
  X(fs__file_write_and_wait_range)                                             \
  X(iomap__iomap_dio_rw)                                                       \
  X(sched__sched_switch)                                                       \
  X(pagecache__delete_from_page_cache)                                         \
  X(pagecache__add_to_page_cache)                                              \
  X(pagecache__mark_page_accessed)                                             \
  X(pagecache__writeback_dirty_page)                                           \
  X(block__bio_queue)                                                          \
  X(block__bio_bounce)                                                         \
  X(block__bio_add_to_rq)                                                      \
  X(block__bio_done)                                                           \
  X(block__bio_throttle)                                                       \
  X(block__rq_insert)                                                          \
  X(block__rq_done)                                                            \
  X(block__rq_issue)                                                           \
  X(block__rq_requeue)                                                         \
  X(nvme__setup_cmd)                                                           \
  X(nvme__complete_rq)                                                         \
  X(nvme__sq)                                                                  \
  X(scsi__dispatch_cmd_start)                                                  \
  X(scsi__dispatch_cmd_error)                                                  \
  X(scsi__dispatch_cmd_done)                                                   \
  X(scsi__dispatch_cmd_timeout)                                                \
  X(virtio__queue_rq)

#define KERNEL_HOOK_TYPE_ENUM(name) name,
enum kernel_hook_type { KERNEL_HOOK_TYPE_DEF(KERNEL_HOOK_TYPE_ENUM) };

#define KERNEL_HOOK_TYPE_STR(name) #name,
static const char *kernel_hook_type_str[] = {
    KERNEL_HOOK_TYPE_DEF(KERNEL_HOOK_TYPE_STR)};

#define LAYER_DEF(X)                                                           \
  X(qemu_layer)                                                                      \
  X(syscall_layer)                                                                   \
  X(fs_layer)                                                                        \
  X(block_layer)                                                                     \
  X(nvme_layer)                                                                      \
  X(scsi_layer)                                                                      \
  X(virtio_layer)

#define LAYER_ENUM(name) name,
enum info_type { LAYER_DEF(LAYER_ENUM) };

#define LAYER_STR(name) #name,
static const char *info_type_str[] = {LAYER_DEF(LAYER_STR)};

#define TRIGGER_TYPE_DEF(X)                                                    \
  X(NOT_PAIR)                                                                      \
  X(ENTRY)                                                                     \
  X(EXIT)

#define TRIGGER_TYPE_ENUM(name) name,
enum trigger_type { TRIGGER_TYPE_DEF(TRIGGER_TYPE_ENUM) };

#define TRIGGER_TYPE_STR(name) #name,
static const char *trigger_type_str[] = {TRIGGER_TYPE_DEF(TRIGGER_TYPE_STR)};
