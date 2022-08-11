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

#ifndef VTYSH_EXTRACT_PL
#include "pathd/path_sbfd_clippy.c"
#endif

#define XPATH_POLICY_BASELEN 100

DEFINE_MTYPE_STATIC(PATHD, PATH_SEGMENT_LIST_SBFD_CONFIG, "Segment List SBFD configuration data");
DEFINE_MTYPE_STATIC(PATHD, PATH_SRPOLICY_SBFD_CONFIG, "SR-Policy SBFD configuration data");

struct zclient *zclient;
struct thread_master *master;

void sbfd_refresh_policy_state(struct srte_sbfd_event *sbfd_event, enum detection_status status)
{
	struct srte_candidate_group *cpath_group, *safe_cg;
	struct srte_candidate *candidate, *safe_cpath;
	struct srte_policy *policy;
	uint32_t cpath_up_count = 0;
	uint32_t policy_up_count = 0;

    policy = sbfd_event->policy;
    sbfd_event->segl->status = status;

	/*sidlist down -> up*/
	RB_FOREACH_SAFE (cpath_group, srte_candidate_group_head, &policy->candidate_groups, safe_cg) 
	{
		cpath_up_count = 0;
		RB_FOREACH_SAFE (candidate, srte_candidate_head, &cpath_group->candidate_paths, safe_cpath)
		{
            if (!candidate->segment_list)
			{
				continue;
			}
			if (candidate->segment_list->status == SRTE_DETECT_UP)
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

int segment_list_up_handle(struct srte_sbfd_event *sbfd_event)
{
    if (sbfd_event->segl->status == SRTE_DETECT_UP)
	{
		/*up -> up do nothing*/
		zlog_info("segment_list_up_handle up event do nothing");
		return 0;
	}
    
	/*sidlist down -> up*/
	enum srte_policy_status old_status;
	enum srte_policy_status new_status;
	old_status = sbfd_event->policy->status;
	sbfd_refresh_policy_state(sbfd_event, SRTE_DETECT_UP);
    new_status = sbfd_event->policy->status;

	if (old_status != SRTE_POLICY_STATUS_UP 
	    && new_status == SRTE_POLICY_STATUS_UP)
	{
        /* policy down -> up*/
        srv6_choose_best_cpath_group(sbfd_event->policy);
		return 0;
	}
	
	if (old_status == SRTE_POLICY_STATUS_UP 
	    && new_status == SRTE_POLICY_STATUS_UP)
	{
        /*policy update*/
		srv6_choose_best_cpath_group(sbfd_event->policy);
		return 0;
	}

    zlog_err("segment_list_up_handle unexpected situation");
	
	return 0;
}

int segment_list_down_handle(struct srte_sbfd_event *sbfd_event)
{
    if (sbfd_event->segl->status == SRTE_DETECT_DOWN)
	{
		/*down -> down do nothing*/
		zlog_info("segment_list_down_handle down event do nothing");
		return 0;
	}

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

int sbfd_status_event_action(struct srte_sbfd_event *sbfd_event, enum bfd_session_state state)
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


int sbfd_status_event(struct thread *thread)
{
	enum bfd_session_state state;
	struct srte_sbfd_event *sbfd_event;
	int ret;

	sbfd_event = THREAD_ARG(thread);
	state = THREAD_VAL(thread);

	ret = sbfd_status_event_action(sbfd_event, state);

	return ret;
}


void sbfd_seglist_status_update(struct bfd_session_params *bsp,
				      const struct bfd_session_status *bss,
				      void *arg)
{
	struct srte_segment_list *segl = arg;
	struct srte_policy *policy = NULL;
	struct srte_sbfd_event sbfd_event;
	struct ipaddr endpoint;
	memset(&endpoint, 0, sizeof(struct ipaddr));

	zlog_info("%s:  vrf %s(%u) bfd state %s -> %s",
			__func__, bfd_sess_vrf(bsp), bfd_sess_vrf_id(bsp),
			bfd_get_status_str(bss->previous_state),
			bfd_get_status_str(bss->state));

	endpoint.ipa_type = IPADDR_V6;
	memcpy(&endpoint.ipaddr_v6, sbfd_sess_get_srpolicy_endpoint(bsp), sizeof(struct in6_addr));
	policy = srte_policy_find(sbfd_sess_get_srpolicy_color(bsp), &endpoint);
    if (!policy)
	{
		zlog_err("sbfd can't find the policy.");
		return;
	}

    sbfd_event.segl = segl;
	sbfd_event.policy = policy;

	if (bss->state == BSS_DOWN && bss->previous_state == BSS_UP) {
		zlog_info( "%s SBFD DOWN", segl->name);
		// seglist sbfd down event
        thread_add_event(master, sbfd_status_event, &sbfd_event, BSS_DOWN, NULL);     		
	}

	if (bss->state == BSS_UP && bss->previous_state != BSS_UP) {
		zlog_info( "%s SBFD UP", segl->name);
		// seglist sbfd up event
        thread_add_event(master, sbfd_status_event, &sbfd_event, BSS_UP, NULL);     		
	}
}

void sr_config_sbfd_apply(struct srte_segment_list *segl, struct srte_policy *policy)
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
    sbfd_sess_set_srpolicy_info(sbs->session, policy->color, &policy->endpoint.ipaddr_v6);
   
    // get all seg
	RB_FOREACH (s_entry, srte_segment_entry_head, &segl->segments) 
	{
		// copy sid to array
		memcpy(&seglist[seg_num], &s_entry->srv6_sid_value.ipaddr_v6, sizeof(struct in6_addr));
		seg_num++;
	}
	// last sid is endpoint
	memcpy(&seglist[seg_num], &policy->endpoint.ipaddr_v6, sizeof(struct in6_addr));
	seg_num++;
    
	// set sidlist info
	sbfd_sess_set_segments(sbs->session, segl->name, seg_num, seglist);

    // set sbfd echo flag
	sbfd_sess_set_sbfd_echo(sbs->session, policy->bfd_config->is_echo);


	/* SBFD just support IPV6. */
	bfd_sess_set_ipv6_addrs(
		sbs->session,
		IN6_IS_ADDR_UNSPECIFIED(&policy->bfd_config->update_source) ? NULL: &policy->bfd_config->update_source,
		&policy->endpoint.ipaddr_v6);

	sbfd_sess_install(sbs->session);

	return;
}

void sr_config_sbfd_remove(struct srte_segment_list *segl, struct srte_policy *policy)
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
	memset(&policy->bfd_config->update_source, 0 , sizeof(struct in6_addr));
}

void sr_sbfd_update_source(struct srte_policy *policy)
{
    return;
}

/*
 * sr_sbfd_show_info - Show the sbfd information.
 */
// void sr_sbfd_show_info(struct vty *vty, const struct srte_segment_list *segl,
// 		       json_object *json)
// {
// 	bfd_sess_show(vty, json, segl->bfd_config->session);
// }


void srte_policy_sbfd_each_seglist_apply(struct srte_policy *policy)
{
	struct srte_candidate *candidate;

	RB_FOREACH (candidate, srte_candidate_head, &policy->candidate_paths) 
	{
		if (candidate->segment_list == NULL) {
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

void path_delete_sbfd_config(struct srte_policy *policy)
{
	if (policy->bfd_config)
	    XFREE(MTYPE_PATH_SRPOLICY_SBFD_CONFIG, policy->bfd_config);
}

void sr_config_sbfd_create(struct srte_policy *policy, bool is_echo)
{

	/* Already configured, skip it. */
	if (policy->bfd_config) {
		SET_FLAG(policy->bfd_config->bfd_flags, SBFD_NEW);
		return ;
	}

	/* Allocate memory for configuration overrides. */
	policy->bfd_config = XCALLOC(MTYPE_PATH_SRPOLICY_SBFD_CONFIG, sizeof(*policy->bfd_config));

	sbfd_for_policy_reset(policy);
	policy->bfd_config->is_echo = is_echo;
	SET_FLAG(policy->bfd_config->bfd_flags, SBFD_NEW);

}

void sr_config_sbfd_destroy(struct srte_policy *policy)
{
	if (policy->bfd_config)
	    SET_FLAG(policy->bfd_config->bfd_flags, SBFD_DELETED);
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
	type = yang_dnode_get_enum(args->dnode, "./type");
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
	sbs->policy_endpoint = policy->endpoint;
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
    uint32_t color, struct ipaddr *endpoint)
{
	struct srte_sbfd_session search;

	search.policy_color = color;
	search.policy_endpoint = *endpoint;

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

	memcpy(&policy->bfd_config->update_source, &source.ipaddr_v6, sizeof(struct in6_addr));
	
	SET_FLAG(policy->bfd_config->bfd_flags, SBFD_MODIFIED);

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

void cli_show_srte_policy_sbfd(struct vty *vty, struct lyd_node *dnode,
			  bool show_defaults)
{
	enum srte_sbfd_type type;
	uint32_t discr;

	type = yang_dnode_get_enum(dnode, "./type");
	discr = yang_dnode_get_uint32(dnode, "./remote-discr");

	if (type == SRTE_SBFD_ECHO) 
	{
		vty_out(vty, "    sbfd echo source-address %s %d %d %d\n",
		    yang_dnode_get_string(dnode, "./source-address"),
			yang_dnode_get_uint8(dnode, "./detect-multiplier"),
			yang_dnode_get_uint32(dnode, "./required-min-receive-interval"),
			yang_dnode_get_uint32(dnode, "./desired-min-transmit-interval"));
	}
	else
	{
		vty_out(vty, "    sbfd enable remote %d source-address %s %d %d %d\n",
		    yang_dnode_get_uint32(dnode, "./remote-discr"),
			yang_dnode_get_string(dnode, "./source-address"),
			yang_dnode_get_uint8(dnode, "./detect-multiplier"),
			yang_dnode_get_uint32(dnode, "./required-min-receive-interval"),
			yang_dnode_get_uint32(dnode, "./desired-min-transmit-interval"));
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
void sbfd_update_flag_one_policy(struct srte_policy *policy)
{
	if (policy->bfd_config &&  !CHECK_FLAG(policy->bfd_config->bfd_active_flags, SBFD_AF_PASSIVE))
	{
		SET_FLAG(policy->bfd_config->bfd_flags, SBFD_MODIFIED);
	}
}

/*traverse policy， change bfd flag to update , callback when encap source-address modify or del */
void sbfd_update_flag_all_policy()
{
	struct srte_policy *policy;
	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
        if (policy->bfd_config &&  !CHECK_FLAG(policy->bfd_config->bfd_active_flags, SBFD_AF_PASSIVE))
		{
			SET_FLAG(policy->bfd_config->bfd_flags, SBFD_MODIFIED);
		}
	}
}

void sbfd_candidate_seglist_disable(struct srte_candidate *candidate)
{
	bool ret = false;

	if (!candidate || !candidate->segment_list || !candidate->policy->bfd_config
	  || CHECK_FLAG(candidate->policy->bfd_config->bfd_active_flags, SBFD_AF_PASSIVE))
	{
		return;
	}

    ret = is_exist_seglist_in_policy_exclude_cpath(candidate->policy, candidate->segment_list, candidate);
	if (!ret)
	{  
		// has no same segmentlist in policy, del bfd session
        sr_config_sbfd_remove(candidate->segment_list, candidate->policy);
	}
	return;
}

DEFPY_NOSH(seamless_bfd_init_param,
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
DEFPY_NOSH(seamless_bfd_init_enable,
      seamless_bfd_init_enable_cmd,
      "sbfd enable remote (0-4294967295)$discr [source-address$has_sip X:X::X:X$srcip]",
      "seamless BFD\n"
      "enable\n"
	  "remote sbfd reflector\n"
	  "remote discriminator\n"
	  "binding source ip address\n"
	  IPV6_STR)
{
    int ret;
	char sip_buf[INET6_ADDRSTRLEN];

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

	if (has_sip != NULL)
	{
	    nb_cli_enqueue_change(vty, "./sbfd[type='iniatior']/source-address", NB_OP_MODIFY, srcip_str);
	}
	else
	{
		if (!IS_IPADDR_V6(&encap_source_address))
		{
            vty_out(vty, "Please config the srv6 encapsulation source-address first or use command : sbfd enable remote discriminator source-address X:X::X:X\n");
			return CMD_WARNING;
		}

		ipaddr2str(&encap_source_address, sip_buf, sizeof(sip_buf));
		nb_cli_enqueue_change(vty, "./sbfd[type='iniatior']/source-address", NB_OP_MODIFY, sip_buf);
	}

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * XPath: /frr-pathd:pathd/srte/policy/sbfd
 */
DEFPY_NOSH(seamless_bfd_echo,
      seamless_bfd_echo_cmd,
      "sbfd echo [source-address$has_sip X:X::X:X$srcip]",
      "seamless BFD\n"
      "echo mode\n"
	  "binding source ip address\n"
	  IPV6_STR)
{
    int ret;
	char sip_buf[INET6_ADDRSTRLEN];

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

	if (has_sip != NULL)
	{
	    nb_cli_enqueue_change(vty, "./sbfd[type='echo']/source-address", NB_OP_MODIFY, srcip_str);
	}
	else
	{
		if (!IS_IPADDR_V6(&encap_source_address))
		{
            vty_out(vty, "Please config the srv6 encapsulation source-address first or use command : sbfd echo source-address X:X::X:X\n");
			return CMD_WARNING;
		}

		ipaddr2str(&encap_source_address, sip_buf, sizeof(sip_buf));
		nb_cli_enqueue_change(vty, "./sbfd[type='echo']/source-address", NB_OP_MODIFY, sip_buf);
	}

	return nb_cli_apply_changes(vty, NULL);
}


DEFPY_NOSH(seamless_bfd_echo_param,
      seamless_bfd_echo_param_cmd,
      "sbfd echo source-address X:X::X:X$srcip (2-255)$detection_multiplier (50-60000)$min_rx (50-60000)$min_tx",
      "seamless BFD\n"
      "echo mode\n"
	  "binding source ip address\n"
	  IPV6_STR
      "Detect Multiplier\n"
      "Required min receive interval\n"
      "Desired min transmit interval\n")
{
	// nb_cli_enqueue_change(vty, "./sbfd[type='echo'][remote-discr='0']", NB_OP_CREATE, NULL);
	// nb_cli_enqueue_change(vty, "./sbfd[type='echo'][remote-discr='0']/source-address", NB_OP_MODIFY, srcip_str);
	// nb_cli_enqueue_change(vty, "./sbfd[type='echo'][remote-discr='0']/detect-multiplier", NB_OP_MODIFY, detection_multiplier_str);
	// nb_cli_enqueue_change(vty, "./sbfd[type='echo'][remote-discr='0']/required-min-receive-interval", NB_OP_MODIFY, min_rx_str);
	// nb_cli_enqueue_change(vty, "./sbfd[type='echo'][remote-discr='0']/desired-min-transmit-interval", NB_OP_MODIFY, min_tx_str);
	// return nb_cli_apply_changes(vty, NULL);

	return CMD_SUCCESS;

}

DEFPY(
      no_seamless_bfd_echo,
      no_seamless_bfd_echo_cmd,
      "no sbfd echo",
	  NO_STR
	  "seamless BFD\n"
      "echo mode\n")
{
	nb_cli_enqueue_change(vty, "./sbfd[type='echo']", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
      no_seamless_bfd_enable,
      no_seamless_bfd_enable_cmd,
      "no sbfd enable",
	  NO_STR
	  "seamless BFD\n"
      "enable\n")
{
	nb_cli_enqueue_change(vty, "./sbfd[type='iniatior']", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static int sbfd_pathd_candidate_removed_handler(struct srte_candidate *candidate)
{
	bool ret = false;

	if (!candidate || !candidate->policy->bfd_config
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

void sr_sbfd_init()
{
	hook_register(pathd_candidate_removed, sbfd_pathd_candidate_removed_handler);

	/* Initialize PATHD client functions */
	bfd_protocol_integration_init(zclient, master);

    /*sbfd commands*/
    install_element(SR_POLICY_NODE, &seamless_bfd_init_enable_cmd);
	install_element(SR_POLICY_NODE, &seamless_bfd_init_param_cmd);
	install_element(SR_POLICY_NODE, &seamless_bfd_echo_cmd);
	install_element(SR_POLICY_NODE, &seamless_bfd_echo_param_cmd);
	install_element(SR_POLICY_NODE, &no_seamless_bfd_echo_cmd);
    install_element(SR_POLICY_NODE, &no_seamless_bfd_enable_cmd);
}
