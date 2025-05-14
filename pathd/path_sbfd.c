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

#include <zebra.h>

#include "memory.h"
#include "log.h"
#include "lib_errors.h"
#include "network.h"

#include "pathd/pathd.h"
#include "pathd/path_zebra.h"
#include "pathd/path_debug.h"
#include "pathd/path_ted.h"
#include "command.h"
#include "lib/bfd.h"
#include "pathd/path_nb.h"
#include "pathd/path_sbfd.h"
#include "lib/northbound_cli.h"

#ifndef VTYSH_EXTRACT_PL
#include "pathd/path_sbfd_clippy.c"
#endif

#define XPATH_POLICY_BASELEN 100
#define SBFD_FIRST_TIMEOUT 60

DEFINE_MTYPE_STATIC(PATHD, PATH_SEGMENT_LIST_SBFD_CONFIG, "Segment List SBFD configuration data");
DEFINE_MTYPE_STATIC(PATHD, PATH_SRPOLICY_SBFD_CONFIG, "SR-Policy SBFD configuration data");
DEFINE_MTYPE_STATIC(PATHD, PATH_SRPOLICY_SBFD_EVENT, "SR-Policy SBFD event msg");

static void sbfd_refresh_policy_state(struct srte_sbfd_event *sbfd_event, enum detection_status status)
{
	struct srte_candidate_group *cpath_group, *safe_cg;
	struct srte_candidate *candidate, *safe_cpath;
	struct srte_policy *policy;
	uint32_t cpath_up_count = 0;
	uint32_t policy_up_count = 0;
	char endpoint[46];

    policy = sbfd_event->policy;
	prefix2str(&policy->endpoint, endpoint, sizeof(endpoint));

	/*sidlist down -> up*/
	RB_FOREACH_SAFE (cpath_group, srte_candidate_group_head, &policy->candidate_groups, safe_cg) 
	{
		cpath_up_count = 0;
		RB_FOREACH_SAFE (candidate, srte_candidate_pref_head, &cpath_group->candidate_paths, safe_cpath)
		{
            if (!candidate->segment_list)
			{
				continue;
			}
			if (candidate->segment_list == sbfd_event->segl)
			{
				zlog_info("SR-TE(%s, %u), sbfd update cpath:%s, status:%s->%s, pref:%u, has_bfd:%u",
						endpoint, policy->color, candidate->name, cpath_status_str(candidate->status), cpath_status_str(status),
						candidate->preference, (CHECK_FLAG(policy->flags, F_POLICY_CONF_BFD) > 0));
				cpath_status_refresh(candidate, status);
			}

			if (candidate->status == SRTE_DETECT_UP)
			{
				cpath_up_count++;
			}
		}
		if (cpath_up_count > 0)
		{
			cpath_group->status = SRTE_DETECT_UP;
			cpath_group->up_cpath_num = cpath_up_count;
			policy_up_count ++;
		}
		else
		{
			cpath_group->status = SRTE_DETECT_DOWN;
			cpath_group->up_cpath_num = 0;
		}
	}
    
	if (policy_up_count > 0)
	{
		policy->status = SRTE_POLICY_STATUS_UP;
		policy->up_cpath_group_num = policy_up_count;
	}
	else
	{
		policy->status = SRTE_POLICY_STATUS_DOWN;
		policy->up_cpath_group_num = 0;
	}
}

static void sbfd_refresh_policy_group_state(struct srte_candidate_group * group)
{
	// struct srte_candidate_group *cpath_group, *safe_cg;
	struct srte_candidate *candidate, *safe_cpath;
	uint32_t cpath_up_count = 0;

	RB_FOREACH_SAFE (candidate, srte_candidate_pref_head, &group->candidate_paths, safe_cpath)
	{
		if (!candidate->segment_list)
		{
			continue;
		}

		if (candidate->status != SRTE_DETECT_DOWN)
		{
			cpath_up_count++;
		}
	}

	if (cpath_up_count > 0)
	{
		group->status = SRTE_DETECT_UP;
		group->up_cpath_num = cpath_up_count;
	}
	else
	{
		group->status = SRTE_DETECT_DOWN;
		group->up_cpath_num = 0;
	}
}

static int segment_list_up_handle(struct srte_sbfd_event *sbfd_event)
{   
	/*sidlist down -> up*/
	enum srte_policy_status new_status;
	sbfd_refresh_policy_state(sbfd_event, SRTE_DETECT_UP);
    new_status = sbfd_event->policy->status;

    if (new_status == SRTE_POLICY_STATUS_UP)
	{
		/*policy update*/
		SET_FLAG(sbfd_event->policy->flags, F_POLICY_TUNNEL_ATTR_UPDATE);
		srv6_choose_best_cpath_group(sbfd_event->policy);
		return 0;
	}

    zlog_err("segment_list_up_handle unexpected situation");
	
	return 0;
}

static int segment_list_down_handle(struct srte_sbfd_event *sbfd_event)
{
	/*sidlist up -> down*/
	enum srte_policy_status old_status;
	enum srte_policy_status new_status;
	old_status = sbfd_event->policy->status;
    sbfd_refresh_policy_state(sbfd_event, SRTE_DETECT_DOWN);
    new_status = sbfd_event->policy->status;

	if (old_status == SRTE_POLICY_STATUS_UP
	    && new_status == SRTE_POLICY_STATUS_DOWN)
	{
        /* policy up -> down*/
        srv6_choose_best_cpath_group(sbfd_event->policy);
		return 0;
	}
	
	if (new_status == SRTE_POLICY_STATUS_UP)
	{
        /*policy update*/
        srv6_choose_best_cpath_group(sbfd_event->policy);
		return 0;
	}
	
	zlog_err("segment_list_down_handle unexpected situation");

	return 0;	
}

static int sbfd_status_event_action(struct srte_sbfd_event *sbfd_event, enum bfd_session_state state)
{
    switch (state)
	{
		case BFD_STATUS_ADMIN_DOWN:
		case BFD_STATUS_DOWN:
            segment_list_down_handle(sbfd_event);
			/* code */
			break;
		case BFD_STATUS_UP:
			segment_list_up_handle(sbfd_event);
			break;
		default:
		    zlog_warn("receive unexpected sbfd state");
			break;
	}

	return 0;
}


static int sbfd_status_event(struct thread *thread)
{
	enum bfd_session_state state;
	struct srte_sbfd_event *sbfd_event;
	int ret;

	sbfd_event = THREAD_ARG(thread);
	state = THREAD_VAL(thread);

	ret = sbfd_status_event_action(sbfd_event, state);

	if (sbfd_event)
	    XFREE(MTYPE_PATH_SRPOLICY_SBFD_EVENT, sbfd_event);

	return ret;
}


void sbfd_seglist_status_update(struct bfd_session_params *bsp,
				      const struct bfd_session_status *bss,
				      void *arg)
{
	struct srte_segment_list *segl = arg;
	struct srte_policy *policy = NULL;
	struct srte_sbfd_event *sbfd_event;
	struct prefix endpoint;
	memset(&endpoint, 0, sizeof(struct ipaddr));

	if (IS_PATHD_DEBUG_SBFD) {
		zlog_debug("%s:  vrf %s(%u) bfd state %s -> %s",
				__func__, bfd_sess_vrf(bsp), bfd_sess_vrf_id(bsp),
				bfd_get_status_str(bss->previous_state),
				bfd_get_status_str(bss->state));
	}
	endpoint.family = AF_INET6;
	endpoint.prefixlen = IPV6_MAX_BITLEN;
	if (IPV6_ADDR_SAME(&bsp->args.sr_endpoint, &in6addr_any))
	    endpoint.prefixlen = 0;

	endpoint.u.prefix6 = bsp->args.sr_endpoint;
	policy = srte_policy_find(sbfd_sess_get_srpolicy_color(bsp), &endpoint);
    if (!policy)
	{
		zlog_err("sbfd can't find the policy.");
		return;
	}
    
	sbfd_event = XCALLOC(MTYPE_PATH_SRPOLICY_SBFD_EVENT, sizeof(struct srte_sbfd_event));
    sbfd_event->segl = segl;
	sbfd_event->policy = policy;

	if (bss->state == BSS_UP)
	{
		// up event stop first sbfd timer
		THREAD_OFF(policy->wait_sbfd_timer);
	}

	if (bss->state == BSS_DOWN && bss->previous_state == BSS_UP) {
		if (IS_PATHD_DEBUG_SBFD)
			zlog_debug( "%s:  sidlist %s SBFD DOWN", __func__, segl->name);
		// seglist sbfd down event
        thread_add_event(master, sbfd_status_event, sbfd_event, BSS_DOWN, NULL);     		
	}

	if (bss->state == BSS_UP && bss->previous_state != BSS_UP) {
		if (IS_PATHD_DEBUG_SBFD)
			zlog_debug( "%s:  sidlist %s SBFD UP", __func__, segl->name);
		// seglist sbfd up event
        thread_add_event(master, sbfd_status_event, sbfd_event, BSS_UP, NULL);     		
	}
}

static void sr_config_sbfd_apply(struct srte_segment_list *segl, struct srte_policy *policy)
{
	struct srte_segment_entry *s_entry;
	uint32_t seg_num = 0;
	struct in6_addr seglist[16];

	/* Create new session and assign callback. */
	struct srte_sbfd_session * sbs;

	sbs = srte_sbfd_session_add(segl, policy);

	bfd_sess_set_timers(sbs->session,
				policy->bfd_config->detection_multiplier,
				policy->bfd_config->min_rx,
				policy->bfd_config->min_tx);
	bfd_sess_set_cbit(sbs->session, policy->bfd_config->cbit);
	bfd_sess_set_profile(sbs->session, policy->bfd_config->profile);

	bfd_sess_set_remote_discr(sbs->session, policy->bfd_config->remote_disc);

	// set policy info
	sbfd_sess_set_srpolicy_info(sbs->session, policy->color, &policy->endpoint.u.prefix6);

    // get all seg
	RB_FOREACH (s_entry, srte_segment_entry_head, &segl->segments) 
	{
		// copy sid to array
		memcpy(&seglist[seg_num], &s_entry->srv6_sid_value.ipaddr_v6, sizeof(struct in6_addr));
		seg_num++;
	}
    
	// set sidlist info
	sbfd_sess_set_segments(sbs->session, segl->name, seg_num, seglist);

    // set sbfd echo flag
	sbfd_sess_set_sbfd_echo(sbs->session, policy->bfd_config->is_echo);


	/* SBFD just support IPV6. */
	if (policy->bfd_config->is_echo)
	{
		if (IS_IPADDR_V6(&policy->bfd_config->update_source))
		{
			bfd_sess_set_ipv6_addrs(
				sbs->session,
				&policy->bfd_config->update_source.ipaddr_v6,
				&policy->bfd_config->update_source.ipaddr_v6);
		}
		else
		{
            bfd_sess_set_ipv4_addrs(
				sbs->session,
				&policy->bfd_config->update_source.ipaddr_v4,
				&policy->bfd_config->update_source.ipaddr_v4);				
		}
	}
	else
	{
		bfd_sess_set_ipv6_addrs(
			sbs->session,
			&policy->bfd_config->update_source.ipaddr_v6,
			&policy->endpoint.u.prefix6);
	}

	if (IS_IPADDR_V6(&encap_source_address)) {
		sbs->session->args.outer_src = encap_source_address.ipaddr_v6;
	}


	sbfd_sess_install(sbs->session);

	return;
}

static void sr_config_sbfd_remove(struct srte_segment_list *segl, struct srte_policy *policy)
{
	/* Create new session and assign callback. */
	struct srte_sbfd_session * sbs;

	sbs =  srte_sbfd_session_find(segl, policy->color, &policy->endpoint);
 	if (sbs == NULL)
	{
		zlog_err(
				"%s: [sbfd] have not sbfd echo config !", __func__);
	    return;
	}

	sbfd_sess_uninstall(sbs->session);

	srte_sbfd_session_del(sbs);

	return;
}

/**
 * Reset SBFD configuration data structure to its defaults settings.
 */
static void sbfd_for_policy_reset(struct srte_policy *policy)
{
	/* Set defaults. */
	policy->bfd_config->detection_multiplier = BFD_DEF_DETECT_MULT;
	policy->bfd_config->min_rx = BFD_DEF_MIN_RX;
	policy->bfd_config->min_tx = BFD_DEF_MIN_TX;
	policy->bfd_config->cbit = false;
	policy->bfd_config->profile[0] = 0;
	policy->bfd_config->update_if[0] = 0;
	memset(&policy->bfd_config->update_source, 0 , sizeof(struct ipaddr));
}

void srte_policy_sbfd_each_seglist_apply(struct srte_policy *policy)
{
	struct srte_candidate *candidate;

	RB_FOREACH (candidate, srte_candidate_head, &policy->candidate_paths) 
	{
		if (candidate->segment_list == NULL) {
			continue;
		}

		if (candidate->bfd_name[0]){
			//bfd_name already attached, ignore
			zlog_warn(
				"cancel sbfd apply on cpath:%s, already bond to bfd:%s", candidate->name, candidate->bfd_name);
			continue;
		}	

		sr_config_sbfd_apply(candidate->segment_list, policy);
	}
}

void srte_policy_sbfd_each_seglist_remove(struct srte_policy *policy)
{
	struct srte_candidate *candidate;

	RB_FOREACH (candidate, srte_candidate_head, &policy->candidate_paths) 
	{
		if (candidate->segment_list == NULL) {
			continue;
		}	
        sr_config_sbfd_remove(candidate->segment_list, policy);
	}
}

void srte_policy_sbfd_each_seglist_del_then_apply(struct srte_policy *policy)
{
	struct srte_candidate *candidate;

	RB_FOREACH (candidate, srte_candidate_head, &policy->candidate_paths) 
	{
		if (candidate->segment_list == NULL) {
			continue;
		}

		if(candidate->bfd_name[0]){
			//bfd_name already attached, ignore
			zlog_warn(
				"cancel sbfd del-apply on cpath:%s, already bond to bfd:%s", candidate->name, candidate->bfd_name);
			continue;
		}

        sr_config_sbfd_remove(candidate->segment_list, policy);
		sr_config_sbfd_apply(candidate->segment_list, policy);
	}
}

void path_delete_sbfd_config(struct srte_policy *policy)
{
	if (policy->bfd_config)
	    XFREE(MTYPE_PATH_SRPOLICY_SBFD_CONFIG, policy->bfd_config);
}

static void sr_config_sbfd_create(struct srte_policy *policy, bool is_echo)
{

	/* Already configured, skip it. */
	if (policy->bfd_config) {
		policy->bfd_config->is_echo = is_echo;
		SET_FLAG(policy->bfd_config->bfd_flags, SBFD_NEW);
		return ;
	}

	/* Allocate memory for configuration overrides. */
	policy->bfd_config = XCALLOC(MTYPE_PATH_SRPOLICY_SBFD_CONFIG, sizeof(*policy->bfd_config));

	sbfd_for_policy_reset(policy);
	policy->bfd_config->is_echo = is_echo;
	SET_FLAG(policy->bfd_config->bfd_flags, SBFD_NEW);

}

static void sr_config_sbfd_destroy(struct srte_policy *policy)
{
	if (policy->bfd_config)
	{
		sbfd_for_policy_reset(policy);
        SET_FLAG(policy->bfd_config->bfd_flags, SBFD_DELETED);
		SET_FLAG(policy->flags, F_POLICY_TUNNEL_ATTR_UPDATE);
	}
}

/*
 * XPath: /frr-pathd:pathd/srte/policy/sbfd-echo
 */
int pathd_srte_policy_sbfd_create(struct nb_cb_create_args *args)
{
	struct srte_policy *policy;
	enum srte_sbfd_type type;
	bool is_echo;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, "type");
	is_echo = (type == SRTE_SBFD_ECHO) ? true : false;

    sr_config_sbfd_create(policy, is_echo);

    SET_FLAG(policy->flags, F_POLICY_CONF_BFD);
	SET_FLAG(policy->flags, F_POLICY_MODIFIED);

	return NB_OK;
}

int pathd_srte_policy_sbfd_destroy(struct nb_cb_destroy_args *args)
{
    struct srte_policy *policy;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);
    sr_config_sbfd_destroy(policy);
    UNSET_FLAG(policy->flags, F_POLICY_CONF_BFD);
	SET_FLAG(policy->flags, F_POLICY_MODIFIED);

	return NB_OK;
}

/**
 * Add a srte_sbfd_session into a segment list.
 *
 * @param segment_list The segment_list to be add entry target
 * @param policy config in the policy
 */
struct srte_sbfd_session *
srte_sbfd_session_add(struct srte_segment_list *segment_list, struct srte_policy *policy)
{
	struct srte_sbfd_session *sbs;

	// first to find is exist or not
	sbs = srte_sbfd_session_find(segment_list, policy->color, &policy->endpoint);
	if (sbs)
	    return sbs;

	sbs = XCALLOC(MTYPE_PATH_SEGMENT_LIST_SBFD_CONFIG, sizeof(*sbs));
	sbs->policy_color = policy->color;
	prefix2ipaddr(&policy->endpoint, &sbs->policy_endpoint);
	sbs->segment_list = segment_list;
	sbs->session = bfd_sess_new(sbfd_seglist_status_update, segment_list);

	RB_INSERT(srte_sbfd_session_head, &segment_list->sbfd_sessions, sbs);

	return sbs;
}

/**
 * Deletes a srte_sbfd_session from a segment list.
 *
 * @param sbs The srte_sbfd_session to be removed
 */
void srte_sbfd_session_del(struct srte_sbfd_session *sbs)
{
	RB_REMOVE(srte_sbfd_session_head, &sbs->segment_list->sbfd_sessions, sbs);
	XFREE(MTYPE_PATH_SEGMENT_LIST_SBFD_CONFIG, sbs);
}

/**
 * Searches for a an entry of a given segment list.
 *
 * @param segment_list The segment list to search for the entry
 * @param color The color of the policy to look for
 * @param endpoint The endpoint of the policy to look for
 * @return The segment list entry if found, NULL otherwise.
 */
struct srte_sbfd_session *srte_sbfd_session_find(struct srte_segment_list *segment_list, 
    uint32_t color, struct prefix *endpoint)
{
	struct srte_sbfd_session search;

	search.policy_color = color;
	prefix2ipaddr(endpoint, &search.policy_endpoint);

	return RB_FIND(srte_sbfd_session_head, &segment_list->sbfd_sessions,
		       &search);
}

/*
 * XPath: /frr-pathd:pathd/srte/policy/sbfd-echo/source-address
 */
int pathd_srte_policy_sbfd_source_address_modify(struct nb_cb_modify_args *args)
{
	struct srte_policy *policy;
	struct ipaddr source;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);

	if (!policy || !policy->bfd_config) 
	{
		flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				"The SR Policy has not sbfd config!");
		return NB_ERR_RESOURCE;
	} 

	yang_dnode_get_ip(&source, args->dnode, NULL);

	memcpy(&policy->bfd_config->update_source, &source, sizeof(struct ipaddr));
	
	if (CHECK_FLAG(policy->bfd_config->bfd_active_flags, SBFD_AF_ACTIVE))
	{
        SET_FLAG(policy->bfd_config->bfd_flags, SBFD_DELADD);
	}
	else
	{
	    SET_FLAG(policy->bfd_config->bfd_flags, SBFD_MODIFIED);
	}

	SET_FLAG(policy->flags, F_POLICY_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/srte/policy/sbfd/remote-discr
 */
int pathd_srte_policy_sbfd_remote_discr_modify(struct nb_cb_modify_args *args)
{
	struct srte_policy *policy;
    uint32_t discr;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);

	if (!policy || !policy->bfd_config) 
	{
		flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				"The SR Policy has not sbfd config!");
		return NB_ERR_RESOURCE;
	} 
    
	discr = yang_dnode_get_uint32(args->dnode, NULL);

	policy->bfd_config->remote_disc = discr;
	
	SET_FLAG(policy->bfd_config->bfd_flags, SBFD_MODIFIED);

	SET_FLAG(policy->flags, F_POLICY_MODIFIED);

	return NB_OK;
}


/*
 * XPath: /frr-pathd:pathd/srte/policy/sbfd/detect-multiplier
 */
int pathd_srte_policy_sbfd_detect_multiplier_modify(struct nb_cb_modify_args *args)
{
	struct srte_policy *policy;
	uint8_t detect_multiplier;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);

	if (!policy || !policy->bfd_config) 
	{
		flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				"The SR Policy has not sbfd config!");
		return NB_ERR_RESOURCE;
	} 

	detect_multiplier = yang_dnode_get_uint8(args->dnode, NULL);
	policy->bfd_config->detection_multiplier = detect_multiplier;
	SET_FLAG(policy->bfd_config->bfd_flags, SBFD_MODIFIED);

	SET_FLAG(policy->flags, F_POLICY_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/srte/policy/sbfd/required-min-receive-interval
 */
int pathd_srte_policy_sbfd_mri_modify(struct nb_cb_modify_args *args)
{
	struct srte_policy *policy;
	uint32_t min_rx;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);

	if (!policy || !policy->bfd_config) 
	{
		flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				"The SR Policy has not sbfd config!");
		return NB_ERR_RESOURCE;
	} 
    
	min_rx = yang_dnode_get_uint32(args->dnode, NULL);
	policy->bfd_config->min_rx = min_rx;
	SET_FLAG(policy->bfd_config->bfd_flags, SBFD_MODIFIED);

	SET_FLAG(policy->flags, F_POLICY_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/srte/policy/sbfd/desired-min-transmit-interval
 */
int pathd_srte_policy_sbfd_mti_modify(struct nb_cb_modify_args *args)
{
	struct srte_policy *policy;
	uint32_t min_tx;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);

	if (!policy || !policy->bfd_config) 
	{
		flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				"The SR Policy has not sbfd config!");
		return NB_ERR_RESOURCE;
	} 
    
	min_tx = yang_dnode_get_uint32(args->dnode, NULL);
	policy->bfd_config->min_tx = min_tx;
	SET_FLAG(policy->bfd_config->bfd_flags, SBFD_MODIFIED);

	SET_FLAG(policy->flags, F_POLICY_MODIFIED);

	return NB_OK;
}

void cli_show_srte_policy_sbfd(struct vty *vty, const struct lyd_node *dnode,
			  bool show_defaults)
{
	enum srte_sbfd_type type;

	type = yang_dnode_get_enum(dnode, "type");

	if (type == SRTE_SBFD_ECHO)
	{
		vty_out(vty, "   sbfd echo source-address %s %d %d %d\n",
		    yang_dnode_get_string(dnode, "source-address"),
			yang_dnode_get_uint8(dnode, "detect-multiplier"),
			yang_dnode_get_uint32(dnode, "required-min-receive-interval"),
			yang_dnode_get_uint32(dnode, "desired-min-transmit-interval"));
	}
	else
	{
		vty_out(vty, "   sbfd enable remote %d source-address %s %d %d %d\n",
		    yang_dnode_get_uint32(dnode, "remote-discr"),
			yang_dnode_get_string(dnode, "source-address"),
			yang_dnode_get_uint8(dnode, "detect-multiplier"),
			yang_dnode_get_uint32(dnode, "required-min-receive-interval"),
			yang_dnode_get_uint32(dnode, "desired-min-transmit-interval"));
	}

}

bool is_exist_seglist_in_policy_exclude_cpath(struct srte_policy *policy, struct srte_segment_list *seglist, 
    struct srte_candidate *ex_cpath)
{
	struct srte_candidate *candidate;
	RB_FOREACH (candidate, srte_candidate_head,  &policy->candidate_paths) {
		if (candidate == ex_cpath)
		{
			continue;
		}

		if (candidate->segment_list == seglist)
		{
			return true;
		}
	}
	return false;
}

bool is_exist_seglist_in_policy(struct srte_policy *policy, struct srte_segment_list *seglist)
{
	struct srte_candidate *candidate;
	RB_FOREACH (candidate, srte_candidate_head,  &policy->candidate_paths) {
		if (candidate->segment_list == seglist)
		{
			return true;
		}
	}
	return false;
}

/*for one policy , update bfd flag, callback when cpath update or create */
void sbfd_update_flag_one_policy(struct srte_policy *policy, uint32_t flag)
{
	if (policy->bfd_config &&  !CHECK_FLAG(policy->bfd_config->bfd_active_flags, SBFD_AF_PASSIVE))
	{
		SET_FLAG(policy->bfd_config->bfd_flags, flag);
	}
}

/*traverse policy change bfd flag to update , callback when encap source-address modify or del */
void sbfd_update_flag_all_policy(uint32_t flag)
{
	struct srte_policy *policy;
	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
        if (policy->bfd_config &&  !CHECK_FLAG(policy->bfd_config->bfd_active_flags, SBFD_AF_PASSIVE))
		{
			SET_FLAG(policy->bfd_config->bfd_flags, flag);
		}
	}
}

void sbfd_sip_update_by_srv6_config()
{
	struct srte_policy *policy;
	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
        if (policy->bfd_config 
		    && !CHECK_FLAG(policy->bfd_config->bfd_active_flags, SBFD_AF_PASSIVE))
		{
			SET_FLAG(policy->bfd_config->bfd_flags, SBFD_DELADD);
		}
	}
}
int _sbfd_candidate_seglist_disable(struct srte_candidate *candidate)
{
	bool ret = false;

	if (!candidate || !candidate->segment_list || !candidate->policy->bfd_config
	    || CHECK_FLAG(candidate->policy->bfd_config->bfd_active_flags, SBFD_AF_PASSIVE))
	{
		return 0;
	}

	ret = is_exist_seglist_in_policy_exclude_cpath(candidate->policy, candidate->segment_list, candidate);
	if (!ret)
	{
		// has no same segmentlist in policy, del bfd session
		sr_config_sbfd_remove(candidate->segment_list, candidate->policy);
	}
	return 0;
}

void sbfd_candidate_seglist_disable(struct srte_candidate *candidate)
{
	_sbfd_candidate_seglist_disable(candidate);
	return;
}

DEFPY(seamless_bfd_init_param,
      seamless_bfd_init_param_cmd,
      "sbfd enable remote (0-4294967295)$discr source-address X:X::X:X$srcip (2-255)$detection_multiplier (50-60000)$min_rx (50-60000)$min_tx",
      "seamless BFD\n"
      "enable\n"
	  "remote sbfd reflector\n"
	  "remote discriminator\n"
	  "binding source ip address\n"
	  IPV6_STR
      "Detect Multiplier\n"
      "Required min receive interval\n"
      "Desired min transmit interval\n")
{
	// char xpath[XPATH_POLICY_BASELEN];
	// snprintf(xpath, sizeof(xpath),
	// 	 "./sbfd[type='iniatior'][remote-discr='%s']", discr_str);
	// nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	// snprintf(xpath, sizeof(xpath),
	// 	 "./sbfd[type='iniatior'][remote-discr='%s']/source-address", discr_str);
	// nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, srcip_str);

	// snprintf(xpath, sizeof(xpath),
	// 	 "./sbfd[type='iniatior'][remote-discr='%s']/detect-multiplier", discr_str);
	// nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, detection_multiplier_str);

	// snprintf(xpath, sizeof(xpath),
	// 	 "./sbfd[type='iniatior'][remote-discr='%s']/required-min-receive-interval", discr_str);
	// nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, min_rx_str);

	// snprintf(xpath, sizeof(xpath),
	// 	 "./sbfd[type='iniatior'][remote-discr='%s']/desired-min-transmit-interval", discr_str);
	// nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, min_tx_str);
	// return nb_cli_apply_changes(vty, NULL);

	return CMD_SUCCESS;
}

/*
 * XPath: /frr-pathd:pathd/srte/policy/sbfd
 */
DEFPY(seamless_bfd_init_enable,
      seamless_bfd_init_enable_cmd,
      "sbfd enable remote (0-4294967295)$discr source-address X:X::X:X$srcip",
      "seamless BFD\n"
      "enable\n"
	  "remote sbfd reflector\n"
	  "remote discriminator\n"
	  "binding source ip address\n"
	  IPV6_STR)
{
    int ret;

	/* del sbfd initiator first */
	nb_cli_enqueue_change(vty, "./sbfd[type='echo']", NB_OP_DESTROY, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	if (ret != NB_OK)
	{
		vty_out(vty, "Delete Sbfd initiator config failed.\n");
		return ret;	
	}

	/*then config sbfd initiator*/
    nb_cli_enqueue_change(vty, "./sbfd[type='iniatior']", NB_OP_CREATE, NULL);
    nb_cli_enqueue_change(vty, "./sbfd[type='iniatior']/remote-discr", NB_OP_MODIFY, discr_str);

	nb_cli_enqueue_change(vty, "./sbfd[type='iniatior']/source-address", NB_OP_MODIFY, srcip_str);

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * XPath: /frr-pathd:pathd/srte/policy/sbfd
 */
DEFPY(seamless_bfd_echo,
      seamless_bfd_echo_cmd,
      "sbfd echo source-address <A.B.C.D|X:X::X:X>$srcip [(2-255)$detection_multiplier (50-60000)$min_rx (50-60000)$min_tx]",
      "seamless BFD\n"
      "echo mode\n"
	  "binding source ip address\n"
	  IP_STR
	  IPV6_STR
      "Detect Multiplier\n"
      "Required min receive interval\n"
      "Desired min transmit interval\n")
{
    int ret;

	/* del sbfd initiator first */
	nb_cli_enqueue_change(vty, "./sbfd[type='iniatior']", NB_OP_DESTROY, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	if (ret != NB_OK)
	{
		vty_out(vty, "Delete Sbfd initiator config failed.\n");
		return ret;	
	}

    /* then config sbfd echo */
	nb_cli_enqueue_change(vty, "./sbfd[type='echo']", NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./sbfd[type='echo']/source-address", NB_OP_MODIFY, srcip_str);

	if (detection_multiplier_str != NULL)
	{
		nb_cli_enqueue_change(vty, "./sbfd[type='echo']/detect-multiplier", NB_OP_MODIFY, detection_multiplier_str);
		nb_cli_enqueue_change(vty, "./sbfd[type='echo']/required-min-receive-interval", NB_OP_MODIFY, min_rx_str);
		nb_cli_enqueue_change(vty, "./sbfd[type='echo']/desired-min-transmit-interval", NB_OP_MODIFY, min_tx_str);		
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_seamless_bfd,
	  no_seamless_bfd_cmd,
      "no sbfd",
	  NO_STR
	  "seamless BFD\n")
{
	int ret;
	nb_cli_enqueue_change(vty, "./sbfd[type='iniatior']", NB_OP_DESTROY, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	if (ret != NB_OK)
	{
		vty_out(vty, "Delete Sbfd initiator config failed.\n");
		return ret;
	}
	nb_cli_enqueue_change(vty, "./sbfd[type='echo']", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static int sbfd_pathd_candidate_status_handler(struct srte_candidate *candidate)
{
	struct srte_sbfd_session *sbs;
    enum bfd_session_state status;

	if (!candidate || !candidate->policy || !candidate->policy->bfd_config || !candidate->segment_list
	  || CHECK_FLAG(candidate->policy->bfd_config->bfd_active_flags, SBFD_AF_PASSIVE))
	{
		return 0;
	}

	sbs = srte_sbfd_session_find(candidate->segment_list, 
	    candidate->policy->color, &candidate->policy->endpoint);
	
	if (!sbs)
        return 0;

	status = bfd_sess_status(sbs->session);
        
	if (candidate->status == SRTE_DETECT_DOWN 
		&& status == BFD_STATUS_UP)
	{
		if (IS_PATHD_DEBUG_SBFD)
			zlog_debug( "%s:  cpath %s's status change to up.", __func__, candidate->name);

		candidate->status = SRTE_DETECT_UP;

		srv6_refresh_policy_state(candidate->policy);
		srv6_choose_best_cpath_group(candidate->policy);
	}
	
	return 0;
}

static int policy_sbfd_first_timeout(struct thread *t)
{
    struct srte_policy *policy = THREAD_ARG(t);
    THREAD_OFF(policy->wait_sbfd_timer);

	struct srte_sbfd_event sbfd_event = {0};
	sbfd_event.policy = policy;

	struct srte_candidate *candidate, *safe;

	RB_FOREACH_SAFE (candidate, srte_candidate_head,
			 &policy->candidate_paths, safe) {
        if (candidate->segment_list == NULL)
		    continue;

        sbfd_event.segl = candidate->segment_list;
	    sbfd_status_event_action(&sbfd_event, BSS_DOWN);
	}
    return 0;
}

void policy_sbfd_enabled(struct srte_policy *policy)
{
    if (policy->wait_sbfd_timer != NULL)
        return;

    thread_add_timer(master, policy_sbfd_first_timeout,
             (void *)policy, SBFD_FIRST_TIMEOUT, &policy->wait_sbfd_timer);
}

static int policy_sbfd_state_change(char *bfd_name, int state, uint32_t my_discr)
{
	struct srte_candidate *candidate;
	enum detection_status new_status = (state == BFD_STATUS_UP?SRTE_DETECT_UP: SRTE_DETECT_DOWN);
	struct srte_candidate_bfd_group* group = NULL;

	zlog_warn( "bfd:%s(%u) update state to:%s", bfd_name, my_discr, bfd_get_status_str(state));
	group = srte_candidate_bfd_group_find(bfd_name);
	if(!group){
		srte_candidate_bfd_group_add_with_status(bfd_name, new_status, my_discr);
		return 0;
	}

	group->status = new_status;
	group->my_discriminator = my_discr;

	RB_FOREACH (candidate, srte_candidate_bfd_head, &group->candidate_paths) 
	{
		candidate->my_discriminator = my_discr;
		if(candidate->status == new_status)
		    continue;
		if (IS_PATHD_DEBUG_SBFD)
			zlog_debug( "cpath:%s state update:%d -> %d", candidate->name, candidate->status, new_status);

		cpath_status_refresh(candidate, new_status);
		//mark cpath group as changed
		SET_FLAG(candidate->group->flags, F_CPATH_GROUP_STATE_CHANGE);

		sbfd_refresh_policy_group_state(candidate->group);
		//simplely assume that different cpath bind to different bfd_name
		//so a policy can bind to a bfd_name only once, we can directly update policy best cpath here
		srv6_choose_best_cpath_group(candidate->policy);
	}

	return 0;
}

void sr_sbfd_init()
{
	/* after add or update cpath case */
    hook_register(pathd_candidate_created, sbfd_pathd_candidate_status_handler);
	hook_register(pathd_candidate_updated, sbfd_pathd_candidate_status_handler);

	/* Initialize PATHD client functions */
	bfd_protocol_integration_init(zclient, master);
	hook_register(sbfd_state_change_hook, policy_sbfd_state_change);

    /*sbfd commands*/
    install_element(SR_POLICY_NODE, &seamless_bfd_init_enable_cmd);
	install_element(SR_POLICY_NODE, &seamless_bfd_init_param_cmd);
	install_element(SR_POLICY_NODE, &seamless_bfd_echo_cmd);
	install_element(SR_POLICY_NODE, &no_seamless_bfd_cmd);
}
