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
#include "block/aio_task.h"
#include "standard-headers/linux/virtio_blk.h"
#include "system_macro.h"
// #include "scsi/pr-manager.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";



// #define DEBUG 1
#ifdef DEBUG
#define bpf_debug(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define bpf_debug(fmt, ...)
#endif
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20);
  __uint(pinning, LIBBPF_PIN_BY_NAME); // 不同文件的 rb 会共享成一个
} ringbuffer SEC(".maps");

// 把 QEMU_EXE 改成你自己编译出来的 QEMU 的路径
#define QEMU_EXE "/home/hrpccs/workspace/qemu-proj/qemu/build/x86_64-softmmu/qemu-system-x86_64"
#define QEMU_HOOK(hook_point_name) "uprobe/" QEMU_EXE ":"  hook_point_name
#define QEMU_RET_HOOK(hook_point_name) "uretprobe/" QEMU_EXE ":"  hook_point_name

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void*);
	__type(value, int);
	__uint(max_entries, 1024);
} virtblk_rq_map SEC(".maps");

// per tid map 记录每个线程的请求对应的偏移
// 因为 QEMU 的协程不会调度的
// 是有必要的，因为 blk_aio_* 不仅仅只有 virtblk 请求会使用
// 主要是避免
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, long long);
	__uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // 不同文件的 rb 会共享成一个
} tid_offset_map SEC(".maps"); 

// tid, rq 
SEC(QEMU_HOOK("virtio_blk_handle_request"))
int BPF_KPROBE(trace_qemu_virtio_blk_handle_request,VirtIOBlockReq *req)
{ 
	// bpf_debug("virtio_blk_handle_request %lx \n", req);
	// store a event to ring buffer
	// struct virtio_blk_outhdr h= BPF_CORE_READ_USER(req, out);
	struct virtio_blk_outhdr h;
	bpf_probe_read(&h, sizeof(h), &(req->out));
	long long offset = 0;
	bpf_probe_read(&offset, sizeof(long long), &(req->sector_num));
	offset = offset << 9;
	int tid = bpf_get_current_pid_tgid() & 0xffffffff;
	int type = 0;
	type = h.type;
	bpf_debug("virtio_blk_handle_request %lx type %x\n", req, type);
	switch (type & ~(VIRTIO_BLK_T_OUT | VIRTIO_BLK_T_BARRIER)) {

		case VIRTIO_BLK_T_IN:{
			int* ref = bpf_map_lookup_elem(&virtblk_rq_map,&req);
			if(ref != NULL){
				bpf_debug("virtio_blk_handle_request %lx already exsit\n", req);
				return 0;
			}
			struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
			if(!e){
				return 0;
			}
			bpf_map_update_elem(&virtblk_rq_map,&req,&type,BPF_ANY);
			bool is_write = type & VIRTIO_BLK_T_OUT;
			e->event_type = qemu__virtio_blk_handle_request;
			e->info_type = qemu_layer;
			e->trigger_type = NOT_PAIR;
			e->timestamp = bpf_ktime_get_ns();
			e->qemu_layer_info.tid = tid;
			e->qemu_layer_info.virt_rq_addr = (long long)req;
			e->qemu_layer_info.rq_type = is_write ? RQ_TYPE_WRITE : RQ_TYPE_READ;
			e->qemu_layer_info.offset = offset;
			 bpf_debug("virtio_blk_handle_request %lx offset %llx\n", req, e->qemu_layer_info.offset);
			bpf_map_update_elem(&tid_offset_map,&tid,&offset,BPF_ANY);
			bpf_ringbuf_submit(e, 0);
			break;
		}
		case VIRTIO_BLK_T_FLUSH:{
			int *ref = bpf_map_lookup_elem(&virtblk_rq_map,&req);
			if(ref != NULL){
				bpf_debug("virtio_blk_handle_request %lx already exsit\n", req);
				return 0;
			}
			struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
			if(!e){
				return 0;
			}
			bpf_map_update_elem(&virtblk_rq_map,&req,&type,BPF_ANY);
			e->event_type = qemu__virtio_blk_handle_request;
			e->info_type = qemu_layer;
			e->trigger_type = NOT_PAIR;
			e->timestamp = bpf_ktime_get_ns();
			e->qemu_layer_info.tid = bpf_get_current_pid_tgid() & 0xffffffff;
			e->qemu_layer_info.virt_rq_addr = (long long)req;
			e->qemu_layer_info.rq_type = RQ_TYPE_FLUSH;
			e->qemu_layer_info.offset = -RQ_TYPE_FLUSH;
			offset = -RQ_TYPE_FLUSH;
			bpf_map_update_elem(&tid_offset_map,&tid,&offset,BPF_ANY);
			bpf_ringbuf_submit(e, 0);
			break;
		}
		 default:
		 			break;
	}

	return 0;
}

SEC(QEMU_HOOK("virtio_blk_req_complete"))
int BPF_KPROBE(trace_qemu_virtio_blk_req_complete,VirtIOBlockReq *req)
{
	int* ref = bpf_map_lookup_elem(&virtblk_rq_map,&req);
	if(ref == NULL){
		bpf_debug("virtio_blk_req_complete %lx not exsit\n", req);
		return 0;
	}
	bpf_map_delete_elem(&virtblk_rq_map,&req);
	struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
	if(!e){
		return 0;
	}
	e->event_type = qemu__virtio_blk_req_complete;
	e->info_type = qemu_layer;
	e->trigger_type = NOT_PAIR;
	e->timestamp = bpf_ktime_get_ns();
	e->qemu_layer_info.tid = bpf_get_current_pid_tgid() & 0xffffffff;
	e->qemu_layer_info.virt_rq_addr = (long long)req;
	e->qemu_layer_info.rq_type = *ref;
	bpf_ringbuf_submit(e, 0);
	bpf_debug("virtio_blk_req_complete %lx\n", req);
	return 0;
}

// 和 virtio_blk_handle_request 会在一个线程里面执行,并且不会出现调度的情况（QEMU 的协程无调度）
// 所以直接根据线程号匹配即可
// blk_aio_pwritev
// tid offset nr_bytes
SEC(QEMU_HOOK("blk_aio_pwritev")) 
int BPF_KPROBE(trace_qemu_blk_aio_pwritev, BlockBackend *blk, int64_t offset, QEMUIOVector *qiov)
{
	// if the offset is not in the map, return
	int tid = bpf_get_current_pid_tgid() & 0xffffffff;
	long long* offset_ref = bpf_map_lookup_elem(&tid_offset_map,&tid);
	if(offset_ref == NULL){
		return 0;
	}
	if(*offset_ref != offset){
		return 0;
	}
	struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
	if(!e){
		return 0;
	}
	e->event_type = qemu__blk_aio_pwritev;
	e->info_type = qemu_layer;
	e->trigger_type = NOT_PAIR;
	e->timestamp = bpf_ktime_get_ns();
	e->qemu_layer_info.rq_type = RQ_TYPE_WRITE;
	e->qemu_layer_info.tid = tid;
	e->qemu_layer_info.offset = offset;
	bpf_ringbuf_submit(e, 0);
	bpf_debug("blk_aio_pwritev tid %d offset %llx\n",tid,offset);
	return 0;
}

// blk_aio_preadv
// tid offset nr_bytes
SEC(QEMU_HOOK("blk_aio_preadv"))
int BPF_KPROBE(trace_qemu_blk_qio_preadv, BlockBackend *blk, int64_t offset, QEMUIOVector *qiov)
{
	// if the offset is not in the map, return
	int tid = bpf_get_current_pid_tgid() & 0xffffffff;
	long long* offset_ref = bpf_map_lookup_elem(&tid_offset_map,&tid);
	if(offset_ref == NULL){
		return 0;
	}
	if(*offset_ref != offset){
		return 0;
	}
	struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
	if(!e){
		return 0;
	}
	e->event_type = qemu__blk_aio_preadv;
	e->info_type = qemu_layer;
	e->trigger_type = NOT_PAIR;
	e->timestamp = bpf_ktime_get_ns();
	e->qemu_layer_info.rq_type = RQ_TYPE_READ;
	e->qemu_layer_info.tid = tid;
	e->qemu_layer_info.offset = offset;
	bpf_ringbuf_submit(e, 0);
	bpf_debug("blk_aio_preadv tid %d offset %llx\n",tid,offset);
	return 0;
}

// blk_aio_flush
// tid
SEC(QEMU_HOOK("blk_aio_flush"))
int BPF_KPROBE(trace_qemu_aio_flush, BlockBackend *blk)
{
	// if the offset is not in the map, return
	int tid = bpf_get_current_pid_tgid() & 0xffffffff;
	long long* offset_ref = bpf_map_lookup_elem(&tid_offset_map,&tid);
	if(offset_ref == NULL){
		return 0;
	}
	if(*offset_ref != -RQ_TYPE_FLUSH){
		return 0;
	}
	struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
	if(!e){
		return 0;
	}
	e->event_type = qemu__blk_aio_flush;
	e->info_type = qemu_layer;
	e->trigger_type = NOT_PAIR;
	e->timestamp = bpf_ktime_get_ns();
	e->qemu_layer_info.rq_type = RQ_TYPE_FLUSH;
	e->qemu_layer_info.tid = tid;
	e->qemu_layer_info.offset = *offset_ref;
	bpf_ringbuf_submit(e, 0);
	bpf_debug("blk_aio_flush tid %d\n",tid);
	return 0;
}

// 沟通 host 和 guest 块设备请求偏移的桥梁
SEC(QEMU_HOOK("qcow2_add_task"))
int BPF_KPROBE(trace_qcow2_co_pwritev_task_entry)
{
	// get from ctx
	int tid = bpf_get_current_pid_tgid() & 0xffffffff;
	long long* guest_offset_ref = bpf_map_lookup_elem(&tid_offset_map,&tid);
	if(guest_offset_ref == NULL){
		return 0;
	}
	if(*guest_offset_ref == -RQ_TYPE_FLUSH){
		return 0;
	}
	long long guest_offset = PT_REGS_PARM6(ctx);
	if(*guest_offset_ref != guest_offset){
		return 0;
	}
	long long file_cluster_offset = PT_REGS_PARM5(ctx);
	long long host_offset = file_cluster_offset + (guest_offset & QCOW2_CLUSTER_SIZE);
	*guest_offset_ref = host_offset;
	bpf_printk("qcow2_add_task file_cluster_offset %llx host_offset %llx guest_offset %llx\n",file_cluster_offset,host_offset,guest_offset);
	return 0;
}

SEC(QEMU_HOOK("qcow2_co_pwritev_part"))
int BPF_KPROBE(trace_qcow2_co_pwritev_part,BlockDriverState *bs, uint64_t offset, uint64_t bytes,
        QEMUIOVector *qiov, size_t qiov_offset, int flags)
{
	int tid = bpf_get_current_pid_tgid() & 0xffffffff;
	long long* offset_ref = bpf_map_lookup_elem(&tid_offset_map,&tid);
	if(offset_ref == NULL){
		return 0;
	}
	if(*offset_ref != offset){
		return 0;
	}
	struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
	if(!e){
		return 0;
	}
	e->event_type = qemu__qcow2_co_pwritev_part;
	e->info_type = qemu_layer;
	e->trigger_type = NOT_PAIR;
	e->timestamp = bpf_ktime_get_ns();
	e->qemu_layer_info.tid = tid;
	e->qemu_layer_info.offset = *offset_ref;
	e->qemu_layer_info.nr_bytes = bytes;
	bpf_ringbuf_submit(e, 0);
	bpf_debug("qcow2_co_pwritev_part offset %lx bytes %lx\n",offset,bytes);
	bpf_debug("qcow2_co_pwritev_part qiov_offset %lx flags %x\n",qiov_offset,flags);
	return 0;
}

// qcow2_co_preadv_part
SEC(QEMU_HOOK("qcow2_co_preadv_part"))
int BPF_KPROBE(trace_qcow2_co_preadv_part,BlockDriverState *bs, uint64_t offset, uint64_t bytes,
		QEMUIOVector *qiov, size_t qiov_offset, int flags)
{
	int tid = bpf_get_current_pid_tgid() & 0xffffffff;
	long long* offset_ref = bpf_map_lookup_elem(&tid_offset_map,&tid);
	if(offset_ref == NULL){
		return 0;
	}
	if(*offset_ref != offset){
		return 0;
	}
	struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
	if(!e){
		return 0;
	}
	e->event_type = qemu__qcow2_co_preadv_part;
	e->info_type = qemu_layer;
	e->trigger_type = NOT_PAIR;
	e->timestamp = bpf_ktime_get_ns();
	e->qemu_layer_info.tid = tid;
	e->qemu_layer_info.offset = *offset_ref;
	e->qemu_layer_info.nr_bytes = bytes;
	bpf_ringbuf_submit(e, 0);
	bpf_debug("qcow2_co_preadv_part offset %lx bytes %lx\n",offset,bytes);
	bpf_debug("qcow2_co_preadv_part qiov_offset %lx flags %x\n",qiov_offset,flags);
	return 0;
}


// qcow2_co_flush_to_os
SEC(QEMU_HOOK("qcow2_co_flush_to_os"))
int BPF_KPROBE(trace_qcow2_co_flush_to_os,BlockDriverState *bs)
{
	int tid = bpf_get_current_pid_tgid() & 0xffffffff;
	long long* offset_ref = bpf_map_lookup_elem(&tid_offset_map,&tid);
	if(offset_ref == NULL){
		return 0;
	}
	if(*offset_ref != -RQ_TYPE_FLUSH){
		return 0;
	}
	struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
	if(!e){
		return 0;
	}
	e->event_type = qemu__qcow2_co_flush_to_os;
	e->info_type = qemu_layer;
	e->trigger_type = NOT_PAIR;
	e->timestamp = bpf_ktime_get_ns();
	e->qemu_layer_info.tid = tid;
	e->qemu_layer_info.offset = *offset_ref;
	bpf_ringbuf_submit(e, 0);
	bpf_debug("qcow2_co_flush_to_os\n");
	return 0;
}

//raw_co_prw
SEC(QEMU_HOOK("raw_co_prw"))
int BPF_KPROBE(trace_raw_co_prw,BlockDriverState *bs, uint64_t offset,
                                   uint64_t bytes)
{

	int tid = bpf_get_current_pid_tgid() & 0xffffffff;
	long long* offset_ref = bpf_map_lookup_elem(&tid_offset_map,&tid);
	if(offset_ref == NULL){
		return 0;
	}
	if(*offset_ref != offset){
		return 0;
	}
	struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
	if(!e){
		return 0;
	}
	e->event_type = qemu__raw_co_prw;
	e->info_type = qemu_layer;
	e->trigger_type = NOT_PAIR;
	e->timestamp = bpf_ktime_get_ns();
	e->qemu_layer_info.tid = tid;
	e->qemu_layer_info.offset = *offset_ref;
	e->qemu_layer_info.nr_bytes = bytes;
	bpf_ringbuf_submit(e, 0);
	bpf_debug("raw_co_prw offset %lx bytes %lx\n",offset,bytes);
	return 0;
}

//raw_co_flush_to_disk
SEC(QEMU_HOOK("raw_co_flush_to_disk"))
int BPF_KPROBE(trace_raw_co_flush_to_disk)
{
	int tid = bpf_get_current_pid_tgid() & 0xffffffff;
	long long* offset_ref = bpf_map_lookup_elem(&tid_offset_map,&tid);
	if(offset_ref == NULL){
		return 0;
	}
	if(*offset_ref != -RQ_TYPE_FLUSH){
		return 0;
	}
	struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
	if(!e){
		return 0;
	}
	e->event_type = qemu__raw_co_flush_to_disk;
	e->info_type = qemu_layer;
	e->trigger_type = NOT_PAIR;
	e->timestamp = bpf_ktime_get_ns();
	e->qemu_layer_info.tid = tid;
	e->qemu_layer_info.offset = *offset_ref;
	bpf_ringbuf_submit(e, 0);
	return 0;
	bpf_debug("raw_co_flush_to_disk\n");
}


//用一个 map 来存线程池中的线程来自与哪个线程  
// 关联线程池，记录异步 io 的发起者和执行者
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void*);
	__type(value, int);
	__uint(max_entries, 1024);
} args_tid_map SEC(".maps");

// 由于这个函数对上层的感知不强，所以下层的 handle_aiocb* 会出现意料之外的
SEC(QEMU_HOOK("raw_thread_pool_submit")) // keep track of thread pool
int BPF_KPROBE(trace_raw_thread_pool_submit, BlockDriverState *bs,
                                               ThreadPoolFunc func, void *opaque)
{
	//  add arg to map
	int tid = bpf_get_current_pid_tgid() & 0xffffffff;
	bpf_map_update_elem(&args_tid_map,&opaque,&tid,BPF_ANY);
	bpf_debug("raw_thread_pool_submit arg %lx tid %d\n",opaque,tid);
	return 0;
}


// 虽然没有偏移从而请求是否已被记录，但是这种事件可以丢掉
SEC(QEMU_HOOK("handle_aiocb_rw"))
int BPF_KPROBE(trace_handle_aiocb_rw,void* opaque)
{
	if(opaque == 0){
		return 0;
	}
	int* tid_ref = bpf_map_lookup_elem(&args_tid_map,&opaque);
	if(tid_ref == NULL){
		return 0;
	}

	struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
	if(!e){
		return 0;
	}
	int tid = bpf_get_current_pid_tgid() & 0xffffffff;
	int prev_tid = *tid_ref;
	long long offset = 0;
	long long* offset_ref = bpf_map_lookup_elem(&tid_offset_map,&prev_tid);
	offset = offset_ref == NULL ? -1000 : *offset_ref;
	bpf_map_update_elem(&tid_offset_map,&tid,&offset,BPF_ANY);
	// bpf_map_update_elem(&aio_task_tid_arg_map,&tid, &opaque,BPF_ANY);
	e->event_type = qemu__handle_aiocb_rw;
	e->info_type = qemu_layer;
	e->trigger_type =ENTRY;
	e->timestamp = bpf_ktime_get_ns(); 
	e->qemu_layer_info.tid = tid;
	e->qemu_layer_info.prev_tid =prev_tid;
	// TODO: for debug
	e->qemu_layer_info.offset = offset;
	bpf_debug("handle_aiocb_rw arg %lx tid %d async_task_tid %d\n",opaque,*tid_ref,e->qemu_layer_info.prev_tid);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC(QEMU_RET_HOOK("handle_aiocb_rw"))
int BPF_KRETPROBE(trace_handle_aiocb_rw_ret)
{

	// delete arg from map
	int tid = bpf_get_current_pid_tgid() & 0xffffffff;
	int prev_tid = 0;
	long long offset = 0;
	long long opaque = 0;
	struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
	if(!e){
		return 0;
	}
	bpf_map_delete_elem(&tid_offset_map,&tid);
	// long long* arg = bpf_map_lookup_elem(&aio_task_tid_arg_map,&tid);
	// if(arg == NULL){
	// 	bpf_ringbuf_discard(e, 0);
	// 	bpf_debug("handle_aiocb_rw ret arg %lx not exsit\n",opaque);
	// 	return 0;
	// }
	// opaque = *arg;
	// bpf_map_delete_elem(&aio_task_tid_arg_map,&tid);
	// bpf_map_delete_elem(&args_tid_map,&opaque);
	e->event_type = qemu__handle_aiocb_rw;
	e->info_type = qemu_layer;
	e->trigger_type =EXIT;
	e->timestamp = bpf_ktime_get_ns(); 
	e->qemu_layer_info.tid = tid;
	e->qemu_layer_info.prev_tid =prev_tid;
	// TODO: for debug
	bpf_ringbuf_submit(e, 0);
	bpf_debug("handle_aiocb_rw ret arg %lx\n",opaque);
	return 0;
}

SEC(QEMU_HOOK("handle_aiocb_flush"))
int BPF_KPROBE(trace_handle_aiocb_flush,void* opaque)
{
	if(opaque == 0){
		return 0;
	}
	int tid = bpf_get_current_pid_tgid() & 0xffffffff;
	int prev_tid = 0;
	long long offset = -RQ_TYPE_FLUSH;
	int* tid_ref = bpf_map_lookup_elem(&args_tid_map,&opaque);
	if(tid_ref == NULL){
		return 0;
	}
	prev_tid = *tid_ref;
	struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
	if(!e){
		return 0;
	}
	bpf_map_update_elem(&tid_offset_map,&tid,&offset,BPF_ANY);
	// bpf_map_update_elem(&aio_task_tid_arg_map,&tid, &opaque,BPF_ANY);
	e->event_type = qemu__handle_aiocb_flush;
	e->info_type = qemu_layer;
	e->trigger_type =ENTRY;
	e->timestamp = bpf_ktime_get_ns(); 
	e->qemu_layer_info.tid = tid;
	e->qemu_layer_info.prev_tid = prev_tid;
	e->qemu_layer_info.offset = -RQ_TYPE_FLUSH;
	bpf_ringbuf_submit(e, 0);
	bpf_debug("handle_aiocb_flush arg %lx\n",opaque);
	return 0;
}

SEC(QEMU_RET_HOOK("handle_aiocb_flush"))
int BPF_KRETPROBE(trace_handle_aiocb_flush_ret)
{
	// delete arg from map
	int tid = bpf_get_current_pid_tgid() & 0xffffffff;
	int prev_tid = 0;
	long long offset = 0;
	long long opaque = 0;
	struct event* e = bpf_ringbuf_reserve(&ringbuffer, sizeof(struct event), 0);
	if(!e){
		return 0;
	}
	// long long* arg = bpf_map_lookup_elem(&aio_task_tid_arg_map,&tid);
	// if(arg == NULL){
	// 	bpf_ringbuf_discard(e, 0);
	// 	bpf_debug("handle_aiocb_flush ret arg %lx not exsit\n",opaque);
	// 	return 0;
	// }
	// opaque = *arg;
	// bpf_map_delete_elem(&aio_task_tid_arg_map,&tid);
	bpf_map_delete_elem(&tid_offset_map,&tid);	
	// bpf_map_delete_elem(&args_tid_map,&opaque);
	e->event_type = qemu__handle_aiocb_flush;
	e->info_type = qemu_layer;
	e->trigger_type =EXIT;
	e->timestamp = bpf_ktime_get_ns();
	e->qemu_layer_info.offset = -RQ_TYPE_FLUSH;
	e->qemu_layer_info.tid = tid;
	e->qemu_layer_info.prev_tid = prev_tid;
	bpf_ringbuf_submit(e, 0);
	bpf_debug("handle_aiocb_flush ret arg %lx\n",opaque);
	return 0;
}
