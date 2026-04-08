/* Tracing for Pathd
 *
 * Copyright (C) 2024  Alibaba, Inc.
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

#if !defined(_PATH_TRACE_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _PATH_TRACE_H

#include "lib/trace.h"

#ifdef HAVE_LTTNG

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER frr_pathd

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "pathd/path_trace.h"

#include <lttng/tracepoint.h>

#include "pathd/pathd.h"

/* clang-format off */

/*
 * Candidate path creation tracepoint.
 * Traces: cpath生成流程
 *   srte_candidate_add() -> 新建candidate + lsp -> 插入RB树 -> 加入group
 */
TRACEPOINT_EVENT(
	frr_pathd,
	cpath_add,
	TP_ARGS(uint32_t, color, const char *, endpoint,
		uint32_t, preference, const char *, name,
		const char *, origin, const char *, originator),
	TP_FIELDS(
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_integer(uint32_t, preference, preference)
		ctf_string(name, name)
		ctf_string(origin, origin)
		ctf_string(originator, originator)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, cpath_add, TRACE_INFO)

/*
 * Candidate path deletion tracepoint.
 * Traces: cpath删除流程
 *   srte_candidate_del() -> 从RB树移除 -> 从group移除 -> 释放资源
 */
TRACEPOINT_EVENT(
	frr_pathd,
	cpath_del,
	TP_ARGS(uint32_t, color, const char *, endpoint,
		uint32_t, preference, const char *, name),
	TP_FIELDS(
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_integer(uint32_t, preference, preference)
		ctf_string(name, name)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, cpath_del, TRACE_INFO)

/*
 * Candidate path added to group tracepoint.
 * Traces: cpath加入group流程
 *   srte_candidate_add_group() -> 查找/创建group -> 插入group RB树
 */
TRACEPOINT_EVENT(
	frr_pathd,
	cpath_add_group,
	TP_ARGS(uint32_t, color, const char *, endpoint,
		uint32_t, preference, const char *, name,
		uint32_t, group_preference),
	TP_FIELDS(
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_integer(uint32_t, preference, preference)
		ctf_string(name, name)
		ctf_integer(uint32_t, group_preference, group_preference)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, cpath_add_group, TRACE_INFO)

/*
 * Candidate path status refresh tracepoint.
 * Traces: cpath状态刷新流程
 *   cpath_status_refresh() -> down_handle / up_handle / none
 */
TRACEPOINT_EVENT(
	frr_pathd,
	cpath_status_refresh,
	TP_ARGS(uint32_t, color, const char *, endpoint,
		const char *, name, uint32_t, preference,
		const char *, old_status, const char *, new_status),
	TP_FIELDS(
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_string(name, name)
		ctf_integer(uint32_t, preference, preference)
		ctf_string(old_status, old_status)
		ctf_string(new_status, new_status)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, cpath_status_refresh, TRACE_INFO)

/*
 * Policy apply changes tracepoint.
 * Traces: srv6_policy_apply_changes()处理cpath的SBFD操作和标志变更
 */
TRACEPOINT_EVENT(
	frr_pathd,
	policy_apply_changes,
	TP_ARGS(uint32_t, color, const char *, endpoint,
		const char *, name, uint32_t, bfd_ops,
		uint32_t, flags),
	TP_FIELDS(
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_string(name, name)
		ctf_integer_hex(uint32_t, bfd_ops, bfd_ops)
		ctf_integer_hex(uint32_t, flags, flags)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, policy_apply_changes, TRACE_INFO)

/*
 * Policy refresh state tracepoint.
 * Traces: srv6_refresh_policy_state() 刷新policy下所有cpath group状态
 */
TRACEPOINT_EVENT(
	frr_pathd,
	policy_refresh_state,
	TP_ARGS(uint32_t, color, const char *, endpoint,
		const char *, old_status, const char *, new_status,
		uint32_t, up_group_num),
	TP_FIELDS(
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_string(old_status, old_status)
		ctf_string(new_status, new_status)
		ctf_integer(uint32_t, up_group_num, up_group_num)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, policy_refresh_state, TRACE_INFO)

/*
 * Best candidate group election tracepoint.
 * Traces: cpath选举流程
 *   srv6_choose_best_cpath_group() -> select_candidate_group() -> 选出best/backup
 */
TRACEPOINT_EVENT(
	frr_pathd,
	cpath_election,
	TP_ARGS(uint32_t, color, const char *, endpoint,
		uint32_t, old_best_pref, uint32_t, new_best_pref,
		uint32_t, old_backup_pref, uint32_t, new_backup_pref,
		const char *, action),
	TP_FIELDS(
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_integer(uint32_t, old_best_pref, old_best_pref)
		ctf_integer(uint32_t, new_best_pref, new_best_pref)
		ctf_integer(uint32_t, old_backup_pref, old_backup_pref)
		ctf_integer(uint32_t, new_backup_pref, new_backup_pref)
		ctf_string(action, action)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, cpath_election, TRACE_INFO)

/*
 * Candidate group selection tracepoint.
 * Traces: srte_policy_select_candidate_group() 逐group遍历选举
 */
TRACEPOINT_EVENT(
	frr_pathd,
	cpath_group_select,
	TP_ARGS(uint32_t, color, const char *, endpoint,
		uint32_t, group_pref, const char *, group_status,
		uint32_t, up_cpath_num, const char *, role),
	TP_FIELDS(
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_integer(uint32_t, group_pref, group_pref)
		ctf_string(group_status, group_status)
		ctf_integer(uint32_t, up_cpath_num, up_cpath_num)
		ctf_string(role, role)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, cpath_group_select, TRACE_INFO)

/*
 * SBFD seglist status update callback tracepoint.
 * Traces: sbfd通知pathd的流程
 *   sbfd_seglist_status_update() -> BFD回调入口 -> 创建event
 */
TRACEPOINT_EVENT(
	frr_pathd,
	sbfd_seglist_status_update,
	TP_ARGS(const char *, seglist_name, uint32_t, color,
		const char *, endpoint, const char *, old_state,
		const char *, new_state, uint32_t, my_discr),
	TP_FIELDS(
		ctf_string(seglist_name, seglist_name)
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_string(old_state, old_state)
		ctf_string(new_state, new_state)
		ctf_integer(uint32_t, my_discriminator, my_discr)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, sbfd_seglist_status_update, TRACE_INFO)

/*
 * SBFD status event processing tracepoint.
 * Traces: pathd处理sbfd消息流程
 *   sbfd_status_event() -> sbfd_status_event_action() -> up/down handle
 */
TRACEPOINT_EVENT(
	frr_pathd,
	sbfd_status_event,
	TP_ARGS(const char *, seglist_name, uint32_t, color,
		const char *, endpoint, const char *, state),
	TP_FIELDS(
		ctf_string(seglist_name, seglist_name)
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_string(state, state)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, sbfd_status_event, TRACE_INFO)

/*
 * SBFD refresh policy state tracepoint.
 * Traces: sbfd_refresh_policy_state() 刷新每个cpath状态
 */
TRACEPOINT_EVENT(
	frr_pathd,
	sbfd_refresh_policy_state,
	TP_ARGS(uint32_t, color, const char *, endpoint,
		const char *, cpath_name, const char *, old_status,
		const char *, new_status, const char *, policy_status),
	TP_FIELDS(
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_string(cpath_name, cpath_name)
		ctf_string(old_status, old_status)
		ctf_string(new_status, new_status)
		ctf_string(policy_status, policy_status)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, sbfd_refresh_policy_state, TRACE_INFO)

/*
 * SBFD config apply tracepoint.
 * Traces: sr_config_sbfd_apply() 安装SBFD会话
 */
TRACEPOINT_EVENT(
	frr_pathd,
	sbfd_config_apply,
	TP_ARGS(const char *, seglist_name, uint32_t, color,
		const char *, endpoint, uint8_t, is_echo,
		uint32_t, remote_disc),
	TP_FIELDS(
		ctf_string(seglist_name, seglist_name)
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_integer(uint8_t, is_echo, is_echo)
		ctf_integer(uint32_t, remote_disc, remote_disc)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, sbfd_config_apply, TRACE_INFO)

/*
 * SBFD config remove tracepoint.
 * Traces: sr_config_sbfd_remove() 卸载SBFD会话
 */
TRACEPOINT_EVENT(
	frr_pathd,
	sbfd_config_remove,
	TP_ARGS(const char *, seglist_name, uint32_t, color,
		const char *, endpoint),
	TP_FIELDS(
		ctf_string(seglist_name, seglist_name)
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, sbfd_config_remove, TRACE_INFO)

/*
 * Policy BFD state change tracepoint.
 * Traces: policy_sbfd_state_change() hook回调处理BFD name关联的cpath状态变更
 */
TRACEPOINT_EVENT(
	frr_pathd,
	policy_bfd_state_change,
	TP_ARGS(const char *, bfd_name, uint32_t, my_discr,
		const char *, state),
	TP_FIELDS(
		ctf_string(bfd_name, bfd_name)
		ctf_integer(uint32_t, my_discriminator, my_discr)
		ctf_string(state, state)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, policy_bfd_state_change, TRACE_INFO)

/*
 * Pathd add SRv6 policy to zebra tracepoint.
 * Traces: pathd下发zebra流程
 *   path_zebra_add_srv6_policy() -> encode -> zebra_send_sr_policy(SET)
 */
TRACEPOINT_EVENT(
	frr_pathd,
	zebra_add_srv6_policy,
	TP_ARGS(uint32_t, color, const char *, endpoint,
		const char *, name, uint32_t, path_num,
		const char *, binding_sid, bool, bsid_valid),
	TP_FIELDS(
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_string(name, name)
		ctf_integer(uint32_t, path_num, path_num)
		ctf_string(binding_sid, binding_sid)
		ctf_integer(uint8_t, bsid_valid, bsid_valid)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, zebra_add_srv6_policy, TRACE_INFO)

/*
 * Pathd delete SRv6 policy from zebra tracepoint.
 * Traces: path_zebra_delete_srv6_policy() -> zebra_send_sr_policy(DELETE)
 */
TRACEPOINT_EVENT(
	frr_pathd,
	zebra_delete_srv6_policy,
	TP_ARGS(uint32_t, color, const char *, endpoint,
		const char *, name),
	TP_FIELDS(
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_string(name, name)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, zebra_delete_srv6_policy, TRACE_INFO)

/*
 * Pathd encode SRv6 policy cpath to zapi tracepoint.
 * Traces: path_zebra_encode_srv6_policy() 收集UP cpath编码到zapi消息
 */
TRACEPOINT_EVENT(
	frr_pathd,
	zebra_encode_srv6_cpath,
	TP_ARGS(uint32_t, color, const char *, endpoint,
		uint32_t, group_pref, const char *, cpath_name,
		const char *, sidlist_name, uint32_t, weight,
		uint32_t, my_discr, uint32_t, flags),
	TP_FIELDS(
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_integer(uint32_t, group_pref, group_pref)
		ctf_string(cpath_name, cpath_name)
		ctf_string(sidlist_name, sidlist_name)
		ctf_integer(uint32_t, weight, weight)
		ctf_integer(uint32_t, my_discriminator, my_discr)
		ctf_integer_hex(uint32_t, flags, flags)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, zebra_encode_srv6_cpath, TRACE_INFO)

/*
 * Pathd add SR policy (MPLS) to zebra tracepoint.
 */
TRACEPOINT_EVENT(
	frr_pathd,
	zebra_add_sr_policy,
	TP_ARGS(uint32_t, color, const char *, endpoint,
		const char *, name, uint32_t, binding_sid,
		uint32_t, label_num),
	TP_FIELDS(
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_string(name, name)
		ctf_integer(uint32_t, binding_sid, binding_sid)
		ctf_integer(uint32_t, label_num, label_num)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, zebra_add_sr_policy, TRACE_INFO)

/*
 * Pathd delete SR policy (MPLS) from zebra tracepoint.
 */
TRACEPOINT_EVENT(
	frr_pathd,
	zebra_delete_sr_policy,
	TP_ARGS(uint32_t, color, const char *, endpoint,
		const char *, name, uint32_t, binding_sid),
	TP_FIELDS(
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_string(name, name)
		ctf_integer(uint32_t, binding_sid, binding_sid)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, zebra_delete_sr_policy, TRACE_INFO)

/*
 * Pathd SR policy notify status from zebra tracepoint.
 */
TRACEPOINT_EVENT(
	frr_pathd,
	zebra_sr_policy_notify_status,
	TP_ARGS(uint32_t, color, const char *, endpoint,
		int, status),
	TP_FIELDS(
		ctf_integer(uint32_t, color, color)
		ctf_string(endpoint, endpoint)
		ctf_integer(int, status, status)
	)
)
TRACEPOINT_LOGLEVEL(frr_pathd, zebra_sr_policy_notify_status, TRACE_INFO)

/* clang-format on */

#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* _PATH_TRACE_H */
