#include <iostream>
#include <string>
#include <set>

#include "zebra/zapi_msg.h"
#include "zebra/zebra_srte.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_vrf.h"

#include "common_utils.h"
#include "rnh_utils.h"


void RnhUtils::dump_rnh_t(struct rnh *rnh, struct rnh_t &r)
{
	r.srte_color = rnh->srte_color;
	r.resolved_route.prefixlen = rnh->resolved_route.prefixlen;
	memcpy(r.resolved_route.endpoint, rnh->resolved_route.u.val, 16);
	r.prefix.prefixlen = rnh->node->p.prefixlen;
	memcpy(r.prefix.endpoint, rnh->node->p.u.val, 16);

	std::string status_str[] = {"INIT", "DOWN", "UP"};
	std::cout << " ------ rnh " << rnh << " color " << r.srte_color
		  << " flag " << int(rnh->srte_color_flag) << " resolved "
		  << common_utils::addr2str(r.resolved_route.endpoint) << "/"
		  << r.resolved_route.prefixlen << " srp_status "
		  << status_str[rnh->srp_status] << std::endl;
}


static void print_rnh_t(const struct rnh_t &rnh)
{
	std::cout << " ------ rnh color " << rnh.srte_color << " prefix "
		  << common_utils::addr2str(rnh.prefix.endpoint) << "/"
		  << rnh.prefix.prefixlen << " resolved_route "
		  << common_utils::addr2str(rnh.resolved_route.endpoint) << "/"
		  << rnh.resolved_route.prefixlen << std::endl;
}


/*
 * Copied from zebra/zebra_rnh.c
 * static inline struct route_table *get_rnh_table(vrf_id_t vrfid, afi_t afi,
safi_t safi)
 * */
static struct route_table *gtest_get_rnh_table()
{
	vrf_id_t vrf_id = 0;
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;

	struct zebra_vrf *zvrf;
	struct route_table *t = NULL;

	zvrf = zebra_vrf_lookup_by_id(vrf_id);
	if (zvrf) {
		if (safi == SAFI_UNICAST)
			t = zvrf->rnh_table[afi];
		else if (safi == SAFI_MULTICAST)
			t = zvrf->rnh_table_multicast[afi];
	}

	return t;
}


const std::vector<struct rnh_list_t> RnhUtils::dump_rnh_table()
{
	std::vector<struct rnh_list_t> res;
	char buff[64];

	struct route_table *rnh_table = gtest_get_rnh_table();
	route_table_iter_t iter;
	struct route_node *rn;

	std::cout << " -- rnh_table count " << rnh_table->count << std::endl;
	route_table_iter_init(&iter, rnh_table);
	while ((rn = route_table_iter_next(&iter))) {
		if (rn->info == NULL)
			continue;

		prefix2str(&rn->p, buff, sizeof(buff));
		std::cout << " ---- At prefix " << buff << " node " << rn
			  << " info " << rn->info << std::endl;

		struct rnh_list_t rnh_list;
		rnh_list.prefix.prefixlen = rn->p.prefixlen;
		memcpy(rnh_list.prefix.endpoint, rn->p.u.val, 16);

		struct rnh *rnh;
		for (rnh = static_cast<struct rnh *>(rn->info); rnh;
		     rnh = rnh->next) {
			rnh_list.rnh.push_back({});
			dump_rnh_t(rnh, rnh_list.rnh.back());
		}
		res.push_back(rnh_list);
	}

	route_table_iter_cleanup(&iter);

	return res;
}


bool RnhUtils::check_rnh_vec(const std::vector<struct rnh_t> &dump_nht,
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


bool RnhUtils::check_rnh_table(
	const std::vector<struct rnh_list_t> &dump_rnh_table,
	const std::vector<struct rnh_list_t> &expect_rnh_table)
{
	if (dump_rnh_table.size() != expect_rnh_table.size()) {
		std::cout << "dump_rnh_table.size = " << dump_rnh_table.size()
			  << ", expect_rnh_table.size = "
			  << expect_rnh_table.size() << std::endl;
		return false;
	}

	for (const auto &expect_rnh_list : expect_rnh_table) {
		bool found = false;
		for (const auto &dump_rnh_list : dump_rnh_table) {
			if (common_utils::is_prefix_t_euqal(
				    &dump_rnh_list.prefix,
				    &expect_rnh_list.prefix)) {
				found = true;

				if (!check_rnh_vec(dump_rnh_list.rnh,
						   expect_rnh_list.rnh)) {
					return false;
				}

				break;
			}
		}

		if (!found) {
			std::cout
				<< "check_rnh_table expected prefix not found: "
				<< common_utils::addr2str(
					   expect_rnh_list.prefix.endpoint)
				<< "/" << expect_rnh_list.prefix.prefixlen
				<< std::endl;
			return false;
		}
	}

	return true;
}
