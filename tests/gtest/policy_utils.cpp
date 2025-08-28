//
// Created by lsn on 2024/12/2.
//

#include "policy_utils.h"

#include <iostream>
#include <string>
#include <map>
#include <cstring> // for strcpy
#include <algorithm>
#include <vector>
#include <gtest/gtest.h>

#include "lib/hash.h"
#include "lib/ipaddr.h"
#include "lib/prefix.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_srte.h"

#include "test_model.h"
#include "common_utils.h"
#include "rnh_utils.h"
#include "rib_utils.h"
#include "pathd/pathd.h"


#define VPN_VRF_ID 0

PolicyUtils policy_utils;
extern struct srte_policy_head srte_policies;

int PolicyUtils::init()
{
	memset(&client, 0, sizeof(zserv));
	return 0;
}

zebra_vrf *PolicyUtils::get_mock_zvrf()
{
	return zvrf;
}

zserv *PolicyUtils::get_mock_client()
{
	return &client;
}

int PolicyUtils::get_srv6_tunnel_from_case_srv6_tunnel_t(
	struct zapi_srv6te_tunnel *zt,
	const std::vector<srv6_sidlist_t> *sidlist)
{

	/* path_num */
	zt->path_num = sidlist->size();
	/* sidlists_old */
	if (sidlist->size() > ZEBRA_SID_LIST_MAX_NUM) {
		return -1;
	}
	for (int i = 0; i < sidlist->size(); i++) {
		strcpy(zt->sidlists[i].sidlist_name,
		       sidlist->at(i).sidlist_name.c_str());
		zt->sidlists[i].weight = sidlist->at(i).weight;
		zt->sidlists[i].flags |= sidlist->at(i).flags;
	}
	return 0;
}

int PolicyUtils::get_policy_from_case_policy_t(struct zapi_sr_policy *zp,
					       const struct policy_t *policy)
{

	int ret = 0;
	struct zapi_srv6te_tunnel srv6_tunnel = {0};

	memset(zp, 0, sizeof(struct zapi_sr_policy));
	/* color */
	zp->color = policy->color;

	/* endpoint */
	ret = common_utils::prefix_t2prefix(&policy->policy_table_key,
					    &zp->endpoint);
	if (ret != 0)
		return ret;
	/* tunnel type */
	zp->tunnel_type = SRTE_TUNNEL_TYPE_SRV6;


	/* srv6 tunnel */
	ret = this->get_srv6_tunnel_from_case_srv6_tunnel_t(
		&srv6_tunnel, &policy->segment_list);
	if (ret != 0) {
		return ret;
	}
	zp->srv6_tunnel = srv6_tunnel;
	zp->status = policy->status;
	return ret;
}

struct stream *PolicyUtils::fill_stream_with_policy(struct zapi_sr_policy *zp)
{
	struct stream *s;
	s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	if (s == nullptr)
		return nullptr;
	zapi_srv6_policy_encode(s, ZEBRA_SRV6_POLICY_SET, zp);
	struct zmsghdr hdr;
	if (!zapi_parse_header(s, &hdr))
		return nullptr;
	return s;
}

int PolicyUtils::add_policy_into_srte_table(
	const struct zebra_state_t &initial_zebra_state)
{
	for (const auto &srte_table : initial_zebra_state.policy_route_table) {
		for (const auto &policy : srte_table.policies) {
			struct zapi_sr_policy zp = {0};
			struct stream *s;
			if (this->get_policy_from_case_policy_t(&zp, &policy) !=
			    0) {
				return -1;
			};

			s = this->fill_stream_with_policy(&zp);
			if (s == nullptr) {
				return -1;
			}
			zread_srv6_policy_set(NULL, NULL, s, this->zvrf);
		}
	}

	return 0;
}

int PolicyUtils::get_input_policy_from_case_api_policy_t(
	struct zapi_sr_policy *zp, const struct api_policy_t *input_policy)
{
	int ret = 0;

	/* color */
	zp->color = input_policy->color;

	/* endpoint */
	ret = common_utils::prefix_t2prefix(&input_policy->endpoint,
					    &zp->endpoint);
	if (ret != 0) {
		std::cout << "get_policy_from_case_policy_t error" << std::endl;
		return ret;
	}
	/* tunnel type */
	zp->tunnel_type = SRTE_TUNNEL_TYPE_SRV6;

	/* srv6 tunnel */
	ret = this->get_srv6_tunnel_from_case_srv6_tunnel_t(
		&zp->srv6_tunnel, &input_policy->sidlists);
	if (ret != 0) {
		std::cout << "get_policy_from_case_policy_t error" << std::endl;
		return ret;
	}

	return 0;
}

void PolicyUtils::set_zvrf(zebra_vrf *zvrf)
{
	this->zvrf = zvrf;
}

void PolicyUtils::add_init_route(const struct zebra_state_t *initial_state,
				 const char *init_route)
{
	struct zapi_route zapi = {0};
	zserv *client = &this->client;
	for (int i = 0; i < initial_state->nhgs.size(); i++) {
		bool found = false;
		for (int j = 0; j < initial_state->policy_route_table.size();
		     j++) {
			if (initial_state->nhgs[i].resolved_nexthops[0].color !=
			    initial_state->policy_route_table[j].color) {
				continue;
			}
			for (int k = 0; k < initial_state->policy_route_table[j]
						    .policies.size();
			     k++) {
				if (std::memcmp(
					    initial_state->nhgs[i]
						    .resolved_nexthops[0]
						    .gate,
					    initial_state->policy_route_table[j]
						    .policies[k]
						    .policy_table_key.endpoint,
					    16) == 0) {

					struct zapi_sr_policy zp;
					get_policy_from_case_policy_t(
						&zp,
						&(initial_state
							  ->policy_route_table
								  [j]
							  .policies[k]));
					RibUtils::get_input_route(&zapi, zp,
								  init_route);
					struct stream *s = RibUtils::
						fill_stream_with_route(&zapi);
					EXPECT_NE(s, nullptr);

					zread_route_add(
						policy_utils.get_mock_client(),
						NULL, s,
						policy_utils.get_mock_zvrf());
					found = true;
					break;
				}
			}
			if (found) {
				break;
			}
		}
	}
}

void dump_rnh_t(struct rnh *rnh, struct rnh_t &r)
{
	r.srte_color = rnh->srte_color;
	r.resolved_route.prefixlen = rnh->resolved_route.prefixlen;
	memcpy(r.resolved_route.endpoint, rnh->resolved_route.u.val, 16);
	r.prefix.prefixlen = rnh->node->p.prefixlen;
	memcpy(r.prefix.endpoint, rnh->node->p.u.val, 16);

	std::string status_str[] = {"INIT", "DOWN", "UP"};
	std::cout << " ------ rnh " << rnh << " color " << r.srte_color
		  << " flag " << int(rnh->type_flags) << " resolved "
		  << common_utils::addr2str(r.resolved_route.endpoint) << "/"
		  << r.resolved_route.prefixlen << " srp_status "
		  << status_str[rnh->srp_status] << std::endl;
}

static void dump_zebra_srv6_policy(struct zebra_sr_policy *policy,
				   struct policy_t &p, uint32_t table_color,
				   route_node *rn)
{
	p.color = table_color;
	p.status = static_cast<policy_status_t>(policy->status);
	std::string status_str[] = {"INIT", "DOWN", "UP"};
	std::cout << " ------ policy " << policy
		  << " status = " << status_str[policy->status] << std::endl;

	p.policy_table_key.prefixlen = rn->p.prefixlen;
	memcpy(p.policy_table_key.endpoint, rn->p.u.val, 16);

	std::cout << " ------ policy.path_num = "
		  << (int)policy->srv6_segment_list.path_num << std::endl;
	for (int i = 0; i < policy->srv6_segment_list.path_num; i++) {
		std::cout << " ------- policy.sidlist " << i << ": "
			  << policy->srv6_segment_list.sidlists[i].sidlist_name
			  << " weight :"
			  << (int)policy->srv6_segment_list.sidlists[i].weight
			  << " Srv6SidListBackup :"
			  << ((policy->srv6_segment_list.sidlists[i].flags) &
			      (SRV6_SID_LIST_BACKUP))
			  << std::endl;
		srv6_sidlist_t sid = {
			policy->srv6_segment_list.sidlists[i].sidlist_name,
			policy->srv6_segment_list.sidlists[i].weight,
			policy->srv6_segment_list.sidlists[i].flags};
		p.segment_list.push_back(sid);
	}

	struct rnh *rnh;
	char buff[64];
	size_t rnh_count = rnh_list_count(&policy->nht);
	if (rnh_count == 0) {
		std::cout << " ------ policy.nht is empty" << std::endl;
	} else {
		std::cout << " ------ policy.nht count is " << rnh_count
			  << std::endl;
		frr_each_safe (rnh_list, &policy->nht, rnh) {
			EXPECT_EQ(policy, rnh->policy);

			memset(buff, 0, sizeof(buff));
			prefix2str(&rnh->node->p, buff, sizeof(buff));
			std::cout << " -------- policy.nht " << rnh
				  << " : rnh.route.prefix " << buff << ", ";
			memset(buff, 0, sizeof(buff));
			prefix2str(&rnh->resolved_route, buff, sizeof(buff));
			std::cout << " rnh.resolved_route " << buff
				  << std::endl;
			p.nht.push_back({});
			dump_rnh_t(rnh, p.nht.back());
		}
	}
}

void PolicyUtils::dump_route_table(struct route_table *table,
				   struct srte_table_t &st)
{
	route_table_iter_t iter;
	struct route_node *rn;
	struct zebra_sr_policy *policy;
	char buff[64];
	int route_count = 0;

	route_table_iter_init(&iter, table);
	while ((rn = route_table_iter_next(&iter))) {
		if (rn->info == NULL)
			continue;
		route_count++;
	}
	std::cout << " -- route_table.count = " << route_count << std::endl;

	route_table_iter_init(&iter, table);
	while ((rn = route_table_iter_next(&iter))) {
		prefix2str(&rn->p, buff, sizeof(buff));
		if (rn->info == NULL) {
			std::cerr << " ---- At prefix " << buff << ", NO POLICY"
				  << std::endl;
			continue;
		}

		std::cout << " ---- At prefix " << buff << std::endl;
		policy = static_cast<zebra_sr_policy *>(rn->info);
		struct policy_t p = {0};
		dump_zebra_srv6_policy(policy, p, st.color, rn);
		st.policies.push_back(p);
	}
	route_table_iter_cleanup(&iter);
}

bool PolicyUtils::check_srte_states(
	const std::map<uint32_t, srte_table_t> &dump_srte_state,
	const struct zebra_state_t &expected_state)
{
	if (dump_srte_state.size() !=
	    expected_state.policy_route_table.size()) {
		std::cout << "dump_srte_table.size() " << dump_srte_state.size()
			  << " != expected_state.policy_route_table.size() "
			  << expected_state.policy_route_table.size()
			  << std::endl;
		return false;
	}

	for (int i = 0; i < expected_state.policy_route_table.size(); i++) {
		if (dump_srte_state.find(
			    expected_state.policy_route_table[i].color) ==
		    dump_srte_state.end()) {

			std::cout << "color "
				  << expected_state.policy_route_table[i].color
				  << " not found" << std::endl;
			return false;
		}
		auto iter = dump_srte_state.find(
			expected_state.policy_route_table[i].color);
		if (expected_state.policy_route_table[i].policies.size() !=
		    iter->second.policies.size()) {
			std::cout << "size"
				  << expected_state.policy_route_table[i]
					     .policies.size()
				  << "dumped size"
				  << iter->second.policies.size()
				  << " not found" << std::endl;
			return false;
		}
		if (!check_polices(iter->second,
				   expected_state.policy_route_table[i])) {
			std::cout << "color "
				  << expected_state.policy_route_table[i].color
				  << " polices not match" << std::endl;
			return false;
		}
	}
	return true;
}

#define SIDLIST_FLAG_MASK 0xfffffff8U

bool PolicyUtils::check_srv6_tunnel(const struct policy_t &dumped,
				    const struct policy_t &expected)
{
	if (dumped.segment_list.size() != expected.segment_list.size()) {
		return false;
	}

	for (auto &exp_sidlist : expected.segment_list) {
		bool found = false;
		for (auto &dump_sidlist : dumped.segment_list) {
			if (exp_sidlist.sidlist_name ==
				    dump_sidlist.sidlist_name &&
			    exp_sidlist.weight == dump_sidlist.weight) {
				found = true;
				if (exp_sidlist.flags !=
				    (dump_sidlist.flags & SIDLIST_FLAG_MASK)) {
					std::cout
						<< "check_srv6_tunnel: sidlist.flags mismatch for "
						<< exp_sidlist.sidlist_name
						<< std::endl;
					return false;
				}
				break;
			}
		}
		if (!found) {
			return false;
		}
	}

	return true;
}


// For bug localization
static void print_policy_t(const struct policy_t &p)
{
	char gate_str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, p.policy_table_key.endpoint, gate_str,
		  sizeof(gate_str));
	std::cout << "Policy " << p.color << " " << gate_str << "/"
		  << p.policy_table_key.prefixlen << " " << p.status
		  << std::endl;

	for (auto &sidlist : p.segment_list) {
		std::cout << " -- " << sidlist.sidlist_name << " "
			  << (int)sidlist.weight << std::endl;
	}

	for (auto &rnh : p.nht) {
		std::cout << " -- rnh color " << rnh.srte_color << " "
			  << common_utils::addr2str(rnh.resolved_route.endpoint)
			  << "/" << rnh.resolved_route.prefixlen << std::endl;
	}
}

static void print_rnh_t(const struct rnh_t &rnh)
{
	std::cout << " ------ rnh color " << rnh.srte_color << " prefix "
		  << common_utils::addr2str(rnh.prefix.endpoint) << "/"
		  << rnh.prefix.prefixlen << " resolved_route "
		  << common_utils::addr2str(rnh.resolved_route.endpoint) << "/"
		  << rnh.resolved_route.prefixlen << std::endl;
}

bool check_rnh_vec(const std::vector<struct rnh_t> &dump_nht,
			     const std::vector<struct rnh_t> &expect_nht)
{
	if (dump_nht.size() != expect_nht.size()) {
		std::cout << "dump_policy.nht.size = " << dump_nht.size()
			  << ", expect_policy.nht.size = " << expect_nht.size()
			  << std::endl;
		return false;
	}

	// TODO: double check whether to ignore orderings
	std::set<int> unvisited_index;
	for (int i = 0; i < dump_nht.size(); i++)
		unvisited_index.insert(i);

	for (int i = 0; i < dump_nht.size(); i++) {
		// Iterating over indexes in unvisited_index
		bool found = false;
		for (auto it = unvisited_index.begin();
		     it != unvisited_index.end();) {
			int j = *it;
			if (dump_nht[i].srte_color ==
				    expect_nht[j].srte_color &&
			    common_utils::is_prefix_t_euqal(
				    &dump_nht[i].resolved_route,
				    &expect_nht[j].resolved_route) &&
			    common_utils::is_prefix_t_euqal(
				    &dump_nht[i].prefix,
				    &expect_nht[j].prefix)) {
				found = true;
				unvisited_index.erase(it);
				break;
			} else {
				it++;
			}
		}

		if (!found) {
			std::cout
				<< "check_rnh_vec rnh mismatch: unexpected nht "
				<< std::endl;
			print_rnh_t(dump_nht[i]);
			return false;
		}
	}

	return true;
}

bool PolicyUtils::check_polices(const struct srte_table_t &dump_table,
				const struct srte_table_t &expected_table)
{
	for (int i = 0; i < expected_table.policies.size(); i++) {
		const policy_t &expected_policy = expected_table.policies[i];
		bool policy_found = false;
		bool policy_match = false;
		for (int j = 0; j < dump_table.policies.size(); j++) {
			const policy_t &actual_policy = dump_table.policies[j];
			if (expected_policy.color == actual_policy.color &&
			    common_utils::is_prefix_t_euqal(
				    &expected_policy.policy_table_key,
				    &actual_policy.policy_table_key)) {
				policy_found = true;
				policy_match =
					(expected_policy.status ==
					 actual_policy.status) &&
					check_srv6_tunnel(actual_policy,
							  expected_policy) &&
					check_rnh_vec(
						actual_policy.nht,
						expected_policy.nht);
				if (!policy_match) {
					std::cout
						<< "policy mismatch found expected::actual"
						<< std::endl;
					print_policy_t(expected_policy);
					print_policy_t(actual_policy);
				}
				break;
			}
		}
		if (!(policy_found && policy_match)) {
			if (!policy_found) {
				std::cout << "Expected policy not found"
					  << std::endl;
			} else {
				std::cout << "Expected policy mismatch"
					  << std::endl;
			}
			return false;
		}
	}
	return true;
}

void free_srte_table_hash(struct hash_bucket *bucket, void *arg)
{
	struct srte_table_key *srte_table =
		(struct srte_table_key *)bucket->data;

	hash_release(srte_table_hash, srte_table);
	return;
}

void dump_srte_hash_bucket(struct hash_bucket *bucket, void *arg)
{
	srte_table_key *srte_table = (srte_table_key *)bucket->data;
	struct srte_table_t st = {0};
	st.color = srte_table->color;
	std::cout << "srte_table for color " << srte_table->color
		  << " route_table at " << srte_table->table << std::endl;
	PolicyUtils::dump_route_table(srte_table->table, st);

	if (arg != nullptr) {
		std::map<uint32_t, srte_table_t> *dump_state =
			(std::map<uint32_t, srte_table_t> *)arg;
		EXPECT_EQ(dump_state->find(srte_table->color),
			  dump_state->end());
		dump_state->emplace(srte_table->color, st);
	}
}

std::vector<struct candidate_t>
dump_candidate_paths(struct srte_candidate_head *paths)
{
	std::vector<struct candidate_t> res;

	struct srte_candidate *candidate;
	RB_FOREACH (candidate, srte_candidate_head, paths) {
		struct candidate_t c = {};
		c.candidate_name = candidate->name;
		c.segment_list_name = candidate->segment_list->name;
		c.preference = candidate->preference;
		c.status = candidate->status;
		res.push_back(c);
	}
	// Optional: sort by Preference
	std::sort(res.begin(), res.end(),
		  [](const candidate_t &a, const candidate_t &b) {
			  if (a.preference != b.preference) {
				  return a.preference < b.preference;
			  }
			  return a.candidate_name < b.candidate_name;
		  });
	return res;
}

std::vector<struct path_policy_t> dump_policies()
{
	std::vector<struct path_policy_t> res;
	struct ipaddr ip;
	char buf[128];

	struct srte_policy *policy;
	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
		struct path_policy_t p = {};
		p.color = policy->color;
		prefix2ipaddr(&policy->endpoint, &ip);
		ipaddr2str(&ip, buf, sizeof(buf));
		p.endpoint = buf;
		p.status = policy->status;
		p.candidate_paths =
			dump_candidate_paths(&policy->candidate_paths);
		res.push_back(p);
	}
	// Optional: sort policies by Endpoint
	std::sort(res.begin(), res.end(),
		  [](const path_policy_t &a, const path_policy_t &b) {
			  if (a.color != b.color) {
				  return a.color < b.color;
			  }
			  return a.endpoint < b.endpoint;
		  });
	return res;
}

bool compare_policy(const struct path_policy_t &a, const struct path_policy_t &b)
{
	// Compare top-level policy fields
	if (a.color != b.color || a.endpoint != b.endpoint ||
	    a.status != b.status) {
		std::cerr << "Mismatch in policy_t fields:\n"
			  << "  color:    " << a.color << " vs " << b.color
			  << "\n"
			  << "  endpoint: '" << a.endpoint << "' vs '"
			  << b.endpoint << "'\n"
			  << "  status:   0x" << std::hex << a.status
			  << " vs 0x" << b.status << std::dec << "\n";
		return false;
	}

	// Compare number of candidate paths
	if (a.candidate_paths.size() != b.candidate_paths.size()) {
		std::cerr << "Mismatch: candidate path count ("
			  << a.candidate_paths.size() << " vs "
			  << b.candidate_paths.size() << ")\n";
		return false;
	}

	// Compare each candidate path
	for (size_t i = 0; i < a.candidate_paths.size(); ++i) {
		const auto &candA = a.candidate_paths[i];
		const auto &candB = b.candidate_paths[i];

		// TODO: enable the comparison of status when BFD is supported
		if (candA.preference != candB.preference ||
		    candA.candidate_name != candB.candidate_name ||
		    candA.segment_list_name != candB.segment_list_name) {
			std::cerr << "Mismatch in candidate[" << i << "]:\n"
				  << "  preference:        " << candA.preference
				  << " vs " << candB.preference << "\n"
				  << "  candidate_name:         '"
				  << candA.candidate_name << "' vs '"
				  << candB.candidate_name << "'\n"
				  << "  segment_list_name: '"
				  << candA.segment_list_name << "' vs '"
				  << candB.segment_list_name << "'\n"
				  << "  status:            0x" << std::hex
				  << candA.status << " vs 0x" << candB.status
				  << std::dec << "\n";
			return false;
		}
	}

	return true;
}
