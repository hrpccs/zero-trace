// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <qemu/osdep.h>
#include "hw/virtio/virtio-blk.h"
#include <stddef.h>
#include "block/thread-pool.h"
#include "event_defs.h"
#include "hook_point.h"
// #include "scsi/pr-manager.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20);
  __uint(pinning, LIBBPF_PIN_BY_NAME); // 不同文件的 rb 会共享成一个
} rb SEC(".maps");

#define QEMU_EXE "/home/hrpccs/workspace/qemu-proj/qemu/build/x86_64-softmmu/qemu-system-x86_64"
#define UPROBE_QEMU_HOOK(hook_point_name) "uprobe/" QEMU_EXE ":"  hook_point_name

SEC(UPROBE_QEMU_HOOK("virtio_blk_handle_request"))
int BPF_KPROBE(uprobe_qemu_2, VirtIOBlockReq *req, MultiReqBuffer *mrb)
{ 
	bpf_printk("virtio_blk_handle_request %lx %lx\n", req, mrb);
	// VirtIODevice* vdev = (VirtIODevice*)BPF_CORE_READ_USER(req,dev);
	VirtIOBlock *vblk;
	VirtIODevice *vdev;
	VirtQueue *vq;
	int queue_index = 0;
	long long offset = 0;
	bpf_probe_read_user(&vq, sizeof(VirtQueue *), &(req->vq));
	// long long nr_bytes = 0;
	bpf_probe_read_user(&offset, sizeof(long long), &(req->sector_num));
	// bpf_probe_read_user(&nr_bytes,sizeof(long long),&(req->qiov.size));
	bpf_probe_read_user(&vblk, sizeof(VirtIOBlock *), &(req->dev));
	vdev = &(vblk->parent_obj);
	int device_id = 0;
	bpf_probe_read_user(&device_id, sizeof(int), &(vdev->device_id));
	bpf_printk("dev_id: %lx, queue_index: %lx,offset: %llx\n", device_id,queue_index, offset << 9);

	// store a event to ring buffer
	struct event* e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
	if(!e){
		return 0;
	}
	// get pid 
	e->event_type = vfs_write_exit;
	e->info_type = vfs_layer;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	// get time
	e->timestamp = bpf_ktime_get_ns();
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("uprobe//home/hrpccs/workspace/qemu-proj/qemu/build/x86_64-softmmu/qemu-system-x86_64:virtio_blk_req_complete")
int BPF_KPROBE(uprobe_qemu_14)
{
	bpf_printk("uprobed_qemu14 \n");
	return 0;
}

// blk_aio_pwritev
SEC("uprobe//home/hrpccs/workspace/qemu-proj/qemu/build/x86_64-softmmu/qemu-system-x86_64:blk_aio_pwritev")
int BPF_KPROBE(uprobe_qemu_3, BlockBackend *blk, int64_t offset, QEMUIOVector *qiov)
{
	size_t nr_bytes = 0;
	bpf_probe_read_user(&nr_bytes, sizeof(long long), &(qiov->size));
	bpf_printk("blk_aio_pwritev, offset: %llx, nr_bytes: %llx\n", offset, nr_bytes);
	return 0;
}

// blk_aio_preadv
SEC("uprobe//home/hrpccs/workspace/qemu-proj/qemu/build/x86_64-softmmu/qemu-system-x86_64:blk_aio_preadv")
int BPF_KPROBE(uprobe_qemu_11, BlockBackend *blk, int64_t offset, QEMUIOVector *qiov)
{
	size_t nr_bytes = 0;
	bpf_probe_read_user(&nr_bytes, sizeof(long long), &(qiov->size));
	bpf_printk("blk_aio_preadv, offset: %llx, nr_bytes: %llx\n", offset, nr_bytes);
	return 0;
}

// blk_aio_flush
SEC("uprobe//home/hrpccs/workspace/qemu-proj/qemu/build/x86_64-softmmu/qemu-system-x86_64:blk_aio_flush")
int BPF_KPROBE(uprobe_qemu_12, BlockBackend *blk)
{
	bpf_printk("blk_aio_flush\n");
	return 0;
}

SEC("uprobe//home/hrpccs/workspace/qemu-proj/qemu/build/x86_64-softmmu/qemu-system-x86_64:qcow2_co_pwritev_part")
int BPF_KPROBE(trace_qcow2_co_pwritev_part,BlockDriverState *bs, uint64_t offset, uint64_t bytes,
        QEMUIOVector *qiov, size_t qiov_offset, int flags)
{
	bpf_printk("qcow2_co_pwritev_part offset %lx bytes %lx\n",offset,bytes);
	bpf_printk("qcow2_co_pwritev_part qiov_offset %lx flags %x\n",qiov_offset,flags);
	return 0;
}
SEC("uprobe//home/hrpccs/workspace/qemu-proj/qemu/build/x86_64-softmmu/qemu-system-x86_64:bdrv_driver_pwritev")
int BPF_KPROBE(trace_bdrv_driver_pwritev,BlockDriverState *bs,
                                            uint64_t offset, uint64_t bytes,
                                            QEMUIOVector *qiov,
                                            size_t qiov_offset, int flags)
{
	bpf_printk("bdrv_driver_pwritev offset %lx bytes %lx\n",offset,bytes);
	bpf_printk("bdrv_driver_pwritev qiov_offset %lx flags %x\n",qiov_offset,flags);
	return 0;
}
//raw_co_prw
SEC("uprobe//home/hrpccs/workspace/qemu-proj/qemu/build/x86_64-softmmu/qemu-system-x86_64:raw_co_prw")
int BPF_KPROBE(trace_raw_co_prw,BlockDriverState *bs, uint64_t offset,
                                   uint64_t bytes)
{
		// bs->opaque
	// int fd = BPF_CORE_READ(s,fd);
	// bpf_printk("raw_co_prw fd %ld offset %lx bytes %lx\n",fd,offset,bytes);
	bpf_printk("raw_co_prw offset %lx bytes %lx\n",offset,bytes);
	return 0;
}

//raw_co_flush_to_disk
SEC("uprobe//home/hrpccs/workspace/qemu-proj/qemu/build/x86_64-softmmu/qemu-system-x86_64:raw_co_flush_to_disk")
int BPF_KPROBE(trace_raw_co_flush_to_disk)
{
	// 获取不了 bs->opaque 的内容
	// BlockDriverState* bs =  (BlockDriverState*)PT_REGS_PARM1(ctx);
	// BDRVRawState *s = (BDRVRawState *)BPF_CORE_READ_USER(bs,opaque);
	// int fd = BPF_CORE_READ_USER(s,fd);
	bpf_printk("raw_co_flush_to_disk\n");
	// bpf_printk("raw_co_flush_to_disk %lx\n",bs);
	return 0;
}

SEC(UPROBE_QEMU_HOOK("raw_thread_pool_submit")) // keep track of thread pool
int BPF_KPROBE(trace_raw_thread_pool_submit, BlockDriverState *bs,
                                               ThreadPoolFunc func, void *opaque)
{
	bpf_printk("raw_thread_pool_submit arg %lx\n",opaque);
	return 0;
}

SEC(UPROBE_QEMU_HOOK("handle_aiocb_rw"))
int BPF_KPROBE(trace_handle_aiocb_rw,void* opaque)
{
	bpf_printk("handle_aiocb_rw arg %lx\n",opaque);
	return 0;
}

SEC(UPROBE_QEMU_HOOK("handle_aiocb_flush"))
int BPF_KPROBE(trace_handle_aiocb_flush,void* opaque)
{
	bpf_printk("handle_aiocb_flush arg %lx\n",opaque);
	return 0;
}
