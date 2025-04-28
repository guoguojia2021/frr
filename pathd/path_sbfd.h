/*
 * Copyright (C) 2020  NetDEF, Inc.
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
 */

#ifndef _FRR_PATHD_SBFD_H_
#define _FRR_PATHD_SBFD_H_

#include "lib/memory.h"
#include "lib/ipaddr.h"
#include "lib/srte.h"
#include "lib/bfd.h"

enum srte_sbfd_type {
    SRTE_SBFD_ECHO = 1,
	SRTE_SBFD_INIATIOR = 2,
};

/* sbfd cli*/
void sr_sbfd_init(void);

void srte_policy_sbfd_each_seglist_apply(struct srte_policy *policy);
void srte_policy_sbfd_each_seglist_remove(struct srte_policy *policy);
void srte_policy_sbfd_each_seglist_del_then_apply(struct srte_policy *policy);

struct srte_sbfd_session *srte_sbfd_session_add(struct srte_segment_list *segment_list, struct srte_policy *policy);
void srte_sbfd_session_del(struct srte_sbfd_session *sbs);
struct srte_sbfd_session *srte_sbfd_session_find(struct srte_segment_list *segment_list, 
    uint32_t color, struct prefix *endpoint);

void sbfd_seglist_status_update(struct bfd_session_params *bsp,
				      const struct bfd_session_status *bss,
				      void *arg);

void sbfd_update_flag_all_policy(uint32_t flag);
void sbfd_sip_update_by_srv6_config(void);
void sbfd_update_flag_one_policy(struct srte_policy *policy, uint32_t flag);
bool is_exist_seglist_in_policy_exclude_cpath(struct srte_policy *policy, struct srte_segment_list *seglist, 
    struct srte_candidate *ex_cpath);
bool is_exist_seglist_in_policy(struct srte_policy *policy, struct srte_segment_list *seglist);
int _sbfd_candidate_seglist_disable(struct srte_candidate *candidate);
void sbfd_candidate_seglist_disable(struct srte_candidate *candidate);

void policy_sbfd_enabled(struct srte_policy *policy);
extern struct zclient *zclient;
extern struct thread_master *master;

#endif /* _FRR_PATHD_SBFD_H_ */
