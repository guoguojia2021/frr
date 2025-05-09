/*********************************************************************
 * Copyright 2014,2015,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * bfd.h: implements the BFD protocol.
 */

#ifndef _BFD_FPM_H_
#define _BFD_FPM_H_
/* BfdFpm message types. */
#include "bfdctl.h"
#include "bfd.h"

#define BFDSYNC_MSG_HDR_LEN (sizeof (bfd_msg_hdr_t))
#define BFDSYNC_PROTO_VERSION 1


typedef enum {
    BFDSYNC_MSG_NONE = 0,
    BFD_CREATE_SESSION,
    BFD_DELETE_SESSION,
    BFD_NOTIFY_UP = 3,
    BFD_NOTIFY_DOWN = 4,
} bfdsync_message_types_t;

typedef struct bfd_msg_hdr_t_
{
  uint8_t version;
  uint8_t msg_type;
  uint16_t msg_len;
} bfd_msg_hdr_t;

typedef enum {
    BPC_TYPE_CLASSIC_BFD = 0,
    BPC_TYPE_SBFD_INIT = 1,
    BPC_TYPE_SBFD_RFLT = 2,
    BPC_TYPE_SBFD_ECHO = 3,
} bfd_msg_bpc_type_t;

typedef struct bfd_msg_data_t_
{
    bool bpc_mhop;
	bool bpc_ipv4;
    char bpc_local[INET6_ADDRSTRLEN];
    char bpc_peer[INET6_ADDRSTRLEN];
    char bpc_vrfname[MAXNAMELEN + 1];
    char bpc_localif[MAXNAMELEN + 1];

	uint8_t bpc_detectmultiplier;
	uint32_t bpc_recvinterval;
	uint32_t bpc_txinterval;
	uint32_t desired_tx_interval;
	uint32_t desired_rx_interval;

	uint32_t bpc_echointerval;

	uint8_t bpc_echo;
	uint8_t bpc_shutdown;

	uint8_t bpc_cbit;

    struct bfd_discrs discrs;
    uint16_t src_port;
    uint16_t dest_port;
    uint8_t ttl;
    uint8_t bpc_type; 
    char bpc_segment[MAXNAMELEN + 1];
    char bpc_endpoint[INET6_ADDRSTRLEN];
    char bfd_name[MAXNAMELEN + 1];

} bfd_msg_data_t;

typedef struct bfd_msg_notify_t_
{
    uint64_t recvCount;
    uint64_t sendCount;
    uint32_t remote_discr;
    char bpc_peer[INET6_ADDRSTRLEN];
    char bfd_name[MAXNAMELEN + 1];
} bfd_msg_notify_t;

/* Zebra header size. */
#define BFDSYNC_HEADER_SIZE             10
#define BFDSYNC_HEADER_MARKER              254


static inline void *bfdsync_msg_data(bfd_msg_hdr_t *hdr)
{
    return ((char *)hdr) + BFDSYNC_MSG_HDR_LEN;
}

extern void bfd_fpm_peer_sendmsg(struct bfd_session *bfd, bool create);
void bfd_fpm_sbfd_reflector_sendmsg(struct sbfd_reflector *sr, bool create);

extern int bfpm_init(struct thread_master *master);

const char *bfd_status_translate(int status);
void extract_segment_from_addr_list(char * segment, size_t max_size, struct in6_addr seg_list[], int seg_num);

#endif /* _BFD_H_ */
