//
// Created by lsn on 2024/12/2.
//
#include "nhg_utils.h"

#include <iostream>
#include <map>
#include <utility>
#include <unordered_set>
#include <queue>
#include <algorithm>
#include <gtest/gtest.h>

#include "lib/hash.h"
#include "zebra/zebra_nhg.h"
#include "zebra/zebra_nhg_private.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_router.h"

#include "common_utils.h"
#include "test_model.h"
#include "nexthop_utils.h"

NHGUtils nhg_utils;

static bool ENABLE_SIDLIST_NHG = false;

void enable_sidlist_nhg()
{
	ENABLE_SIDLIST_NHG = true;
}

void reset_sidlist_nhg()
{
	ENABLE_SIDLIST_NHG = false;
}

int NHGUtils::init()
{
	return 0;
}
void NHGUtils::set_zvrf(zebra_vrf *zvrf)
{
	this->zvrf = zvrf;
}
// int NHGUtils::add_nhg_info(std::vector<nhg_t> *nhgs)
//{
//	for (std::vector<nhg_t>::iterator iter = nhgs->begin();
//	     iter != nhgs->end(); iter++) {
//		int ret = 0;
//
//		ret = register_rnh_from_nhg_t(&(*iter));
//		if (ret != 0) {
//			return ret;
//		}
//	}
//	return 0;
// }

// int NHGUtils::register_rnh_from_nhg_t(struct nhg_t *nhg_t)
//{
//
//	struct prefix p;
//	bool exist;
//	int ret = 0;
//	uint8_t srte_color_flag = 0;
//	uint32_t srte_color = 0;
//	struct rnh *rnh;
//	std::cout << "add nhg_t " << nhg_t->nexthop.color << " "
//		  << common_utils::addr2str(nhg_t->nexthop.gate)
//		  << std::endl;
//	srte_color = nhg_t->nexthop.color;
//	// ret = common_utils::prefix_t2prefix(&nhg_t->nexthop.gate, &p);
//	ret = common_utils::addr2prefix(nhg_t->nexthop.gate, &p);
//	if (ret != 0) {
//		return ret;
//	}
//
//	rnh = zebra_add_rnh(&p, zvrf_id(this->zvrf), &exist, srte_color,
//			    srte_color_flag);
//	if (!rnh)
//		return -1;
//	/*
//		if (CHECK_FLAG(flags, NEXTHOP_REGISTER_FLAG_EXTRAMATCH) &&
//		    !CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED))
//			SET_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED);
//		else if (!CHECK_FLAG(flags, NEXTHOP_REGISTER_FLAG_EXTRAMATCH) &&
//			 CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED))
//			UNSET_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED);
//	*/
//
//	/* Anything not AF_INET/INET6 has been filtered out above */
//	if (!srte_color)
//		return -1;
//	zebra_evaluate_rnh_by_srte(family2afi(p.family), rnh);
//	std::cout << "Addition successful" << std::endl;
//	return 0;
// }

struct nhg_processing_node {
	struct nhg_hash_entry *nhg_entry;
	std::vector<uint32_t> seg_depends;
	std::vector<uint32_t> seg_dependents;
	std::vector<struct nexthop_t> resolved_nexthops;

	// Updated during BFS
	std::unordered_set<uint32_t> pending_seg_depends;
};

/*
 * Logs test failure if there is ID conflict between nhg_hash_entry
 */
static void dump_nhgs_hash_bucket(struct hash_bucket *bucket, void *arg)
{
	nhg_hash_entry *nhg_entry = (nhg_hash_entry *)bucket->data;
	nhg_segment *rb_node_dep = nullptr;
	nhg_segment *rb_node_dependent = nullptr;

	std::cout << "zrouter.nhgs entry " << nhg_entry << ", flags "
		  << nhg_entry->flags << ", flag & NEXTHOP_GROUP_SEGMENTLIST = "
		  << (nhg_entry->flags & NEXTHOP_GROUP_SEGMENTLIST) << ", id "
		  << nhg_entry->id << std::endl;
	std::cout << " -- backup_info " << nhg_entry->backup_info << std::endl;

	std::vector<struct nexthop_t> nexthops =
		NexthopUtils::dump_nexthop_group(nhg_entry->nhg);

	struct nhg_processing_node entry_node = nhg_processing_node{0};
	entry_node.nhg_entry = nhg_entry;
	entry_node.resolved_nexthops = std::move(nexthops);

	frr_each_safe (nhg_segment_tree, &nhg_entry->nhg_segdepends,
		       rb_node_dep) {
		std::cout << " -- segdepends " << rb_node_dep->nhe << ", id "
			  << rb_node_dep->nhe->id << std::endl;
		entry_node.seg_depends.push_back(rb_node_dep->nhe->id);
		entry_node.pending_seg_depends.insert(rb_node_dep->nhe->id);
	}

	frr_each_safe (nhg_segment_tree, &nhg_entry->nhg_segdependents,
		       rb_node_dependent) {
		std::cout << " -- segdependent " << rb_node_dependent->nhe
			  << ", id " << rb_node_dependent->nhe->id << std::endl;
		entry_node.seg_dependents.push_back(rb_node_dependent->nhe->id);
	}

	if (arg != nullptr) {
		std::map<uint32_t, struct nhg_processing_node> *nhg_entry_map =
			static_cast<std::map<uint32_t,
					     struct nhg_processing_node> *>(
				arg);
		EXPECT_EQ(nhg_entry_map->find(nhg_entry->id),
			  nhg_entry_map->end())
			<< "nhg_hash_entry id conflict " << nhg_entry->id;
		nhg_entry_map->emplace(nhg_entry->id, entry_node);
	}
	std::cout << std::endl;
}

std::vector<struct nhg_t> NHGUtils::dump_nhgs()
{
	std::map<uint32_t, struct nhg_processing_node> nhg_entry_map;
	hash_iterate(zrouter.nhgs, dump_nhgs_hash_bucket, &nhg_entry_map);

	// Debugging nhg_processing_node, TODO: delete later
	std::cout << "NHGUtils::dump_nhgs (C state) found nhg_entries.size "
		  << nhg_entry_map.size() << std::endl;
	for (std::map<uint32_t, struct nhg_processing_node>::iterator iter =
		     nhg_entry_map.begin();
	     iter != nhg_entry_map.end(); iter++) {
		struct nhg_hash_entry *nhg_entry = iter->second.nhg_entry;
		std::cout << "nhg_hash_entry.id " << nhg_entry->id << " ";
		if (iter->second.seg_dependents.empty()) {
			std::cout << "dependents EMPTY, ";
		} else {
			std::cout << "dependents";
			for (uint32_t id : iter->second.seg_dependents) {
				std::cout << " " << id;
			}
			std::cout << ", ";
		}

		if (iter->second.seg_depends.empty()) {
			std::cout << "depends EMPTY" << std::endl;
		} else {
			std::cout << "depends";
			for (uint32_t id : iter->second.seg_depends) {
				std::cout << " " << id;
			}
			std::cout << std::endl;
		}
	}

	// BFS to dump from leaf nodes
	std::queue<uint32_t> queue;
	std::map<uint32_t, struct nhg_t> res_map;
	for (std::map<uint32_t, struct nhg_processing_node>::iterator iter =
		     nhg_entry_map.begin();
	     iter != nhg_entry_map.end(); iter++) {
		if (iter->second.pending_seg_depends.empty()) {
			queue.push(iter->first);
		}
	}
	while (!queue.empty()) {
		uint32_t id = queue.front();
		queue.pop();
		struct nhg_processing_node &processing_node = nhg_entry_map[id];

		struct nhg_t abs_nhg = {};
		abs_nhg.contains_id = true;
		abs_nhg.internal_id = id;

		abs_nhg.resolved_nexthops =
			std::move(processing_node.resolved_nexthops);

		for (uint32_t depend_id : processing_node.seg_depends) {
			const struct nhg_t &depend_nhg = res_map[depend_id];
			if (depend_nhg.seg_depends.empty() &&
			    depend_nhg.shared_seg_depends.empty()) {
				// sidlist-level depend nhg_t, exclusively owned
				// by its policy
				abs_nhg.seg_depends.push_back(depend_nhg);
				if (!ENABLE_SIDLIST_NHG) {
					res_map.erase(depend_id);
				}
			} else {
				// Otherwise, can be shared by multiple routes
				abs_nhg.shared_seg_depends.push_back(depend_id);
			}
		}
		res_map[id] = abs_nhg;

		for (uint32_t dependent_id : processing_node.seg_dependents) {
			EXPECT_EQ(nhg_entry_map[dependent_id]
					  .pending_seg_depends.erase(id),
				  1)
				<< "nhg_entry double link error at id "
				<< dependent_id << " " << id << std::endl;
			if (nhg_entry_map[dependent_id]
				    .pending_seg_depends.empty()) {
				queue.push(dependent_id);
			}
		}
	}

	std::vector<struct nhg_t> res;
	for (const auto &pair : res_map) {
		res.push_back(pair.second);
	}

	return res;
}


/*
 * returns true if v1 and v2 contains the same set of IDs, ignoring orders
 * */
static bool id_list_eq(const std::vector<int> v1, const std::vector<int> v2,
		       const std::map<int, int> v1_to_v2)
{
	if (v1.size() != v2.size()) {
		return false;
	}

	std::vector<int> sv1;
	for (const int &id : v1) {
		sv1.push_back(v1_to_v2.at(id));
	}
	std::vector<int> sv2 = v2;
	std::sort(sv1.begin(), sv1.end());
	std::sort(sv2.begin(), sv2.end());

	return sv1 == sv2;
}


static bool match_nhg_t_list(const std::vector<nhg_t> &expected_state,
			     const std::vector<nhg_t> &dump_state,
			     std::map<int, int> &dump_to_expected_id)
{
	if (expected_state.size() != dump_state.size()) {
		std::cout << "nhgs.size mismatch: expected_state.size "
			  << expected_state.size() << ", dump_state.size "
			  << dump_state.size() << std::endl;
		return false;
	}

	// Find matching nhg_t by comparing nexthops
	for (auto &expected_nhg : expected_state) {
		bool found = false;
		for (auto &dump_nhg : dump_state) {
			if (dump_nhg.seg_depends.size() ==
				    expected_nhg.seg_depends.size() &&
			    NexthopUtils::nexthop_list_match(
				    expected_nhg.resolved_nexthops,
				    dump_nhg.resolved_nexthops)) {
				found = true;
				if (!match_nhg_t_list(expected_nhg.seg_depends,
						      dump_nhg.seg_depends,
						      dump_to_expected_id)) {
					std::cout
						<< "Expected nhg_entry.segdepends mismatch"
						<< std::endl;
					return false;
				}
				if (!id_list_eq(dump_nhg.shared_seg_depends,
						expected_nhg.shared_seg_depends,
						dump_to_expected_id)) {
					std::cout
						<< "Expected nhg_entry.shared_seg_depends mismatch"
						<< std::endl;
					std::cout << "Expected: ";
					for (const int &i :
					     expected_nhg.shared_seg_depends) {
						std::cout << i << " ";
					}
					std::cout << std::endl;
					std::cout << "Actual: ";
					for (const int &i :
					     dump_nhg.shared_seg_depends) {
						std::cout << i << " ";
					}
					std::cout << std::endl;
					return false;
				}
				if (dump_nhg.contains_id &&
				    expected_nhg.contains_id) {
					dump_to_expected_id
						[dump_nhg.internal_id] =
							expected_nhg
								.internal_id;
				}
				break;
			}
		}

		if (!found) {
			std::cout << "Expected nhg_t not found" << std::endl;
			std::cout << "Expected nhg.segdepends.size"
				  << expected_nhg.seg_depends.size()
				  << " nhg.nexthop " << std::endl;
			for (auto &n : expected_nhg.resolved_nexthops) {
				print_nexthops(n);
			}

			std::cout << "Dumped nhgs " << std::endl;
			for (auto &dump_nhg : dump_state) {
				std::cout << "segdepends.size "
					  << dump_nhg.seg_depends.size()
					  << " nexthop " << std::endl;
				for (auto &n : dump_nhg.resolved_nexthops) {
					print_nexthops(n);
				}
			}
			return false;
		}
	}

	return true;
}


bool NHGUtils::check_nhg_state(const std::vector<nhg_t> &expected_state,
			       const std::vector<nhg_t> &dump_state)
{
	std::map<int, int> dump_to_expected_id;

	// reorder expected_state so that sidlist-level policy-level route-level
	// entries appear in order
	std::vector<nhg_t> expected_sorted_1;
	for (const nhg_t &nhg : expected_state) {
		if (nhg.shared_seg_depends.empty()) {
			expected_sorted_1.insert(expected_sorted_1.begin(),
						 nhg);
		} else {
			expected_sorted_1.push_back(nhg);
		}
	}

	std::vector<nhg_t> expected_sorted_2;
	for (const nhg_t &nhg : expected_sorted_1) {
		if (nhg.shared_seg_depends.empty() && nhg.seg_depends.empty()) {
			expected_sorted_2.insert(expected_sorted_2.begin(),
						 nhg);
		} else {
			expected_sorted_2.push_back(nhg);
		}
	}

	bool res = match_nhg_t_list(expected_sorted_2, dump_state,
				    dump_to_expected_id);

	if (!dump_to_expected_id.empty()) {
		std::cout << "dump_to_expected_id: ";
		for (const auto &pair : dump_to_expected_id) {
			std::cout << pair.first << "->" << pair.second << " ";
		}
		std::cout << std::endl;
	}

	return res;
}


/*
 * Generating necessary routes to enable nhgs in the initial state
 * */

struct nhg_t_processing_node {
	int id; // negative for nhgs without specified ID
	int refCnt;
	std::vector<struct api_route_nexthop_t> api_nexthops;
};


static bool all_depends_processed(
	const struct nhg_t &nhg,
	const std::map<int, struct nhg_t_processing_node> &nexthop_map)
{
	for (int i : nhg.shared_seg_depends) {
		if (nexthop_map.find(i) == nexthop_map.end()) {
			// nhg_id not processed yet
			return false;
		}
	}

	return true;
}


std::vector<struct api_route_t>
NHGUtils::gen_route_for_nhgs(const std::vector<struct nhg_t> &nhgs)
{
	std::vector<struct api_route_t> res;
	std::map<int, struct nhg_t_processing_node> nexthop_map;
	int unique_id = -1;

	std::vector<int> indexes;
	for (int i = 0; i < nhgs.size(); i++) {
		indexes.push_back(i);
	}

	while (!indexes.empty()) {
		bool changed = false;
		for (auto it = indexes.begin(); it != indexes.end();) {
			const struct nhg_t &nhg = nhgs[*it];
			if (all_depends_processed(nhg, nexthop_map)) {
				it = indexes.erase(it);
				changed = true;

				struct nhg_t_processing_node node = {};
				if (!nhg.shared_seg_depends.empty()) {
					// route-level nhg_entry
					for (int seg_id :
					     nhg.shared_seg_depends) {
						struct nhg_t_processing_node
							&d_node = nexthop_map
								[seg_id];
						d_node.refCnt++;
						node.api_nexthops.insert(
							node.api_nexthops.end(),
							d_node.api_nexthops
								.begin(),
							d_node.api_nexthops
								.end());
					}
				} else if (!nhg.seg_depends.empty()) {
					// policy-level nhg_entry
					for (const nexthop_t &n :
					     nhg.resolved_nexthops) {
						struct api_route_nexthop_t
							api_n = {};
						api_n.color = n.color;
						std::memcpy(api_n.gate, n.gate,
							    sizeof(api_n.gate));
						node.api_nexthops.push_back(
							api_n);
					}
				}

				node.id = nhg.contains_id ? nhg.internal_id
							  : unique_id--;
				EXPECT_EQ(nexthop_map.end(),
					  nexthop_map.find(node.id))
					<< "nhgs ID conflict " << node.id
					<< std::endl;
				nexthop_map.emplace(node.id, node);
			} else {
				it++;
			}
		}

		if (!changed) {
			std::cerr << "gen_route_for_nhgs: no progress"
				  << std::endl;
			return res;
		}
	}

	// Add route for each nhg_entry with refCnt 0
	struct prefix_t base_prefix = {};
	// 10.0.0.0/24
	base_prefix.prefixlen = 24;
	base_prefix.endpoint[0] = 0x0a;

	int i = 0;
	for (const auto &pair : nexthop_map) {
		if (pair.second.refCnt == 0) {
			struct api_route_t route = {};
			route.api_nexthops = pair.second.api_nexthops;
			route.prefix = base_prefix;
			route.prefix.endpoint[2] = i;
			i++;

			if (i >= 255) {
				base_prefix.endpoint[1]++;
				i = 0;
			}

			res.push_back(route);
		}
	}

	return res;
}
