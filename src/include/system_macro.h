#pragma once

#define QCOW2_CLUSTER_SIZE 65535

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)

#define SECTOR_SHIFT 9

#define VIRTIO_BLK_T_IN		0
#define VIRTIO_BLK_T_OUT	1

#ifndef VIRTIO_BLK_NO_LEGACY
/* This bit says it's a scsi command, not an actual read or write. */
#define VIRTIO_BLK_T_SCSI_CMD	2
#endif /* VIRTIO_BLK_NO_LEGACY */

/* Cache flush command */
#define VIRTIO_BLK_T_FLUSH	4

/* Get device ID command */
#define VIRTIO_BLK_T_GET_ID    8

/* Discard command */
#define VIRTIO_BLK_T_DISCARD	11

/* Write zeroes command */
#define VIRTIO_BLK_T_WRITE_ZEROES	13

#ifndef VIRTIO_BLK_NO_LEGACY
/* Barrier before this op. */
#define VIRTIO_BLK_T_BARRIER	0x80000000
#endif /* !VIRTIO_BLK_NO_LEGACY */