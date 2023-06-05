#pragma once

#define KERNEL_HOOK_TYPE_DEF(X)                                                \
  X(vfs_read_enter)                                                            \
  X(vfs_write_enter)                                                           \
  X(vfs_read_exit)                                                             \
  X(vfs_write_exit)                                                            \
  X(block_bio_backmerge)                                                       \
  X(block_bio_bounce)                                                          \
  X(block_bio_complete)                                                        \
  X(block_bio_frontmerge)                                                      \
  X(block_bio_queue)                                                           \
  X(block_bio_remap)                                                           \
  X(block_dirty_buffer)                                                        \
  X(block_getrq)                                                               \
  X(block_plug)                                                                \
  X(block_rq_complete)                                                         \
  X(block_rq_insert)                                                           \
  X(block_rq_issue)                                                            \
  X(block_rq_merge)                                                            \
  X(block_rq_remap)                                                            \
  X(block_rq_requeue)                                                          \
  X(block_split)                                                               \
  X(block_touch_buffer)                                                        \
  X(block_unplug)                                                              \
  X(rq_qos_merge)                                                              \
  X(rq_qos_track)                                                              \
  X(rq_qos_done)                                                               \
  X(rq_qos_requeue)                                                            \
  X(filemap_get_pages_enter)                                                   \
  X(filemap_get_pages_exit)                                                    \
  X(filemap_range_needs_writeback_enter)                                       \
  X(filemap_range_needs_writeback_exit)                                        \
  X(filemap_write_and_wait_range_enter)                                        \
  X(filemap_write_and_wait_range_exit)                                         \
  X(mark_page_accessed)                                                        \
  X(iomap_dio_rw_enter)                                                        \
  X(iomap_dio_rw_exit) \
  X(__cond_resched_enter) \
  X(__cond_resched_exit) \

#define KERNEL_HOOK_TYPE_ENUM(name) name,
enum kernel_hook_type { KERNEL_HOOK_TYPE_DEF(KERNEL_HOOK_TYPE_ENUM) };

#define KERNEL_HOOK_TYPE_STR(name) #name,
static const char *kernel_hook_type_str[] = {
    KERNEL_HOOK_TYPE_DEF(KERNEL_HOOK_TYPE_STR)};

#define LAYER_DEF(X)                                                           \
  X(vfs_layer)                                                                 \
  X(bio_info)                                                                  \
  X(rq_info)                                                                   \
  X(bio_rq_association_info)                                                   \
  X(rq_plug_info)                                                              \
  X(bio_bvec_info)

#define LAYER_ENUM(name) name,
enum info_type { LAYER_DEF(LAYER_ENUM) };

#define LAYER_STR(name) #name,
static const char *info_type_str[] = {LAYER_DEF(LAYER_STR)};
