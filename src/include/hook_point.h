#pragma once

#define KERNEL_HOOK_TYPE_DEF(X)                                                \
  X(submit_bio)                                                                \
  X(bio_endio)                                                                 \
  X(ext4_map_blocks_exit)                                                      \
  X(vfs_read_enter)                                                            \
  X(vfs_write_enter)                                                           \
  X(vfs_read_exit)                                                             \
  X(vfs_write_exit)                                                            \
  X(sys_enter_read)                                                            \
  X(sys_exit_read)                                                             \
  X(sys_enter_write)                                                           \
  X(sys_exit_write)                                                            \
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
  X(block_unplug)

#define KERNEL_HOOK_TYPE_ENUM(name) name,
enum kernel_hook_type { KERNEL_HOOK_TYPE_DEF(KERNEL_HOOK_TYPE_ENUM) };

#define KERNEL_HOOK_TYPE_STR(name) #name,
static const char *kernel_hook_type_str[] = {
    KERNEL_HOOK_TYPE_DEF(KERNEL_HOOK_TYPE_STR)};

#define LAYER_DEF(X)                                                           \
  X(block_layer)                                                               \
  X(vfs_layer)                                                                 \
  X(bio_info)                                                                  \
  X(rq_info)

#define LAYER_ENUM(name) name,
enum info_type { LAYER_DEF(LAYER_ENUM) };

#define LAYER_STR(name) #name,
static const char *info_type_str[] = {LAYER_DEF(LAYER_STR)};
