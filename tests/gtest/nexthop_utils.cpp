#include "nexthop_utils.h"

#include <gtest/gtest.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <algorithm>

#include "lib/hash.h"
#include "lib/nexthop.h"
#include "lib/nexthop_group.h"

#include "common_utils.h"


struct nexthop_processing_node {
	struct nexthop *n;
	std::vector<struct nexthop *> resolved;
};


static bool is_a_tree_helper(struct nexthop *n,
			     std::unordered_set<struct nexthop *> visited)
{
	if (n == nullptr) {
		return true;
	}

	if (visited.find(n) != visited.end()) {
		return false;
	} else {
		visited.insert(n);
	}

	return is_a_tree_helper(n->next, visited) &&
	       is_a_tree_helper(n->resolved, visited);
}

/*
 * DFS, returns true (is a valid nexthop tree) if there is no back-edge
 * */
static bool is_a_tree(struct nexthop *n)
{
	return is_a_tree_helper(n, std::unordered_set<struct nexthop *>());
}


static void dump_nexthop(const struct nexthop *n,
			 std::unordered_set<const struct nexthop *> &set)
{
	set.insert(n);
	char gate_str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &n->gate.ipv6, gate_str, INET6_ADDRSTRLEN);

	char seg6_src[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &n->seg6_src, seg6_src, INET6_ADDRSTRLEN);

	char src[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &n->src.ipv6, src, INET6_ADDRSTRLEN);

	std::cout << " -- nexthop " << n << ", type " << n->type << ", ifindex "
		  << n->ifindex << ", flags " << n->flags << ", src " << src
		  << ", gate.ipv6 " << gate_str << ", srte_color "
		  << n->srte_color << ", srte_color_flag " << n->srte_color_flag
		  << ", seg6_sec " << seg6_src << ", sidlist_name "
		  << n->sidlist_name << std::endl;


	std::cout << " ---- nexthop.resolved " << n->resolved
		  << ", nexthop.next " << n->next << ", rparent " << n->rparent
		  << std::endl;

	if (n->nh_srv6) {
		std::cout << ", nh_srv6 " << n->nh_srv6;
	}
	std::cout << std::endl;
}


static std::vector<struct nexthop_t>
dump_abs_nexthops(const struct nexthop *n,
		  std::unordered_set<const struct nexthop *> &validation_set)
{
	std::vector<struct nexthop_t> res;

	while (n != nullptr) {
		// Validation
		EXPECT_TRUE(validation_set.find(n) != validation_set.end())
			<< "nexthop " << n << " not present in ALL_NEXTHOPS set"
			<< std::endl;
		validation_set.erase(n);

		struct nexthop_t t = nexthop_t{0};

		t.color = n->srte_color;
		t.sidlist_name = n->sidlist_name;

		common_utils::v6addrcpy_ipv6(t.gate, n->gate.ipv6);
		t.resolved = dump_abs_nexthops(n->resolved, validation_set);

		res.push_back(t);
		n = n->next;
	}

	return res;
}


std::vector<struct nexthop_t>
NexthopUtils::dump_nexthop_group(struct nexthop_group &nhg)
{
	EXPECT_TRUE(is_a_tree(nhg.nexthop));

	// Debugging output
	const struct nexthop *nexthop = NULL;
	std::unordered_set<const struct nexthop *> validation_set;
	for (ALL_NEXTHOPS(nhg, nexthop)) {
		dump_nexthop(nexthop, validation_set);
	}

	// DFS
	std::vector<struct nexthop_t> res =
		dump_abs_nexthops(nhg.nexthop, validation_set);

	// Validation
	EXPECT_TRUE(validation_set.empty())
		<< validation_set.size() << " nexthops not collected"
		<< std::endl;
	for (auto &n : validation_set) {
		std::cout << "nexthop " << n << " not collected" << std::endl;
	}

	return res;
}


bool NexthopUtils::nexthop_match(const struct nexthop_t &exp_n,
				 const struct nexthop_t &dump_n)
{
	if (exp_n.color != dump_n.color ||
	    exp_n.sidlist_name != dump_n.sidlist_name ||
	    exp_n.resolved.size() != dump_n.resolved.size() ||
	    std::memcmp(exp_n.gate, dump_n.gate, sizeof(exp_n.gate)) != 0) {
		return false;
	}

	// Compare resolved nexthops, ignoring order
	// TODO: sort and compare or hash map
	for (auto &exp_n_resolved : exp_n.resolved) {
		bool found = false;
		for (auto &dump_n_resolved : dump_n.resolved) {
			if (nexthop_match(exp_n_resolved, dump_n_resolved)) {
				found = true;
				break;
			}
		}
		if (!found) {
			return false;
		}
	}

	return true;
}


bool NexthopUtils::nexthop_list_match(
	const std::vector<struct nexthop_t> &exp_nl,
	const std::vector<struct nexthop_t> &dump_nl)
{
	if (exp_nl.size() != dump_nl.size()) {
		return false;
	}

	// Compare ignoring order
	// TODO: sort and compare or hash map
	for (auto &exp_n : exp_nl) {
		bool found = false;
		for (auto &dump_n : dump_nl) {
			if (nexthop_match(exp_n, dump_n)) {
				found = true;
				break;
			}
		}
		if (!found) {
			return false;
		}
	}

	return true;
}

int height(const struct nexthop_t &n)
{
	int resolved_height = 0;
	for (auto &resolved : n.resolved) {
		resolved_height = std::max(resolved_height, height(resolved));
	}
	return resolved_height + 1;
}
