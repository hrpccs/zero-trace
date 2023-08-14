# qemu 关键挂载点语义分析

本文档挂载点都在[这里](../src/qemu_uprobe.bpf.c)

## qemu__virtio_blk_handle_request

## qemu__virtio_blk_req_complete

## qemu__blk_aio_pwritev

## qemu__blk_aio_preadv

## qemu__blk_aio_flush

## qemu__qcow2_co_pwritev_part

## qemu__qcow2_co_preadv_part

## qemu__qcow2_co_flush_to_os

## qemu__raw_co_prw

## qemu__raw_co_flush_to_disk

## qemu__handle_aiocb_rw

## qemu__handle_aiocb_flush