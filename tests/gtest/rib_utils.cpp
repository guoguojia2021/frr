#include <iostream>
#include <string>
#include <set>
#include <gtest/gtest.h>

#include "zebra/zapi_msg.h"
#include "zebra/zebra_srte.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rib.h"
#include "lib/nexthop.h"

#include "common_utils.h"
#include "rib_utils.h"


void RibUtils::dump_nhe_t(struct nexthop *nh, struct nhe_t &nhe)
{
	nhe.color = nh->srte_color;
	std::memcpy(nhe.gate, nh->gate.ipv6.__in6_u.__u6_addr8, 16);

	std::cout << " ------ nexthop " << nh << " color " << nhe.color
		  << " gate " << common_utils::addr2str(nhe.gate) << std::endl;
}


static void print_nhe_t(const struct nhe_t &nhe)
{
	std::cout << " ------ nhe color " << nhe.color << " gate "
		  << common_utils::addr2str(nhe.gate) << std::endl;
}


static struct route_table *gtest_zebra_vrf_table()
{
	vrf_id_t vrf_id = 0;
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;

	struct zebra_vrf *zvrf;
	struct route_table *t = NULL;

	zvrf = zebra_vrf_lookup_by_id(vrf_id);
	if (zvrf) {
		t = zvrf->table[afi][safi];
	}

	return t;
}


const std::vector<struct api_route_t> RibUtils::dump_rib_state()
{
	std::vector<struct api_route_t> res;
	char buff[64];

	struct route_table *table = gtest_zebra_vrf_table();
	route_table_iter_t iter;
	struct route_node *rn;
	struct route_entry *re;
	std::cout << " -- rib count " << table->count << std::endl;
	route_table_iter_init(&iter, table);
	while ((rn = route_table_iter_next(&iter))) {
		if (rn->info == NULL)
			continue;

		prefix2str(&rn->p, buff, sizeof(buff));
		std::cout << " ---- At prefix " << buff << " node " << rn
			  << " info " << rn->info << std::endl;

		struct api_route_t route;
		route.prefix.prefixlen = rn->p.prefixlen;
		std::memcpy(route.prefix.endpoint, rn->p.u.val, 16);

		rib_dest_t *dest = (rib_dest_t *)rn->info;
		RNODE_FOREACH_RE (rn, re) {
			if (re->type == ZEBRA_ROUTE_BGP)
				break;
		}
		if (re == NULL) {
			std::cout << " ---- no route entry" << std::endl;
			continue;
		}
		for (nexthop *nh = re->nhe->nhg.nexthop; nh; nh = nh->next) {
			route.route_entry.push_back({});
			dump_nhe_t(nh, route.route_entry.back());
		}
		res.push_back(route);
	}

	route_table_iter_cleanup(&iter);

	return res;
}

bool RibUtils::check_route_entry(
	const std::vector<struct nhe_t> &dump_route_entry,
	const std::vector<struct nhe_t> &expect_route_entry)
{
	if (dump_route_entry.size() != expect_route_entry.size()) {
		std::cout << "dump_rib_state.route_entry.size = "
			  << dump_route_entry.size()
			  << ", expect_rib_state.route_entry.size = "
			  << expect_route_entry.size() << std::endl;
		return false;
	}

	// TODO: double check whether to ignore orderings
	std::set<int> unvisited_index;
	for (int i = 0; i < dump_route_entry.size(); i++)
		unvisited_index.insert(i);

	for (int i = 0; i < dump_route_entry.size(); i++) {
		// Iterating over indexes in unvisited_index
		bool found = false;
		for (auto it = unvisited_index.begin();
		     it != unvisited_index.end();) {
			int j = *it;

			if (dump_route_entry[i].color ==
				    expect_route_entry[j].color &&
			    std::memcmp(dump_route_entry[i].gate,
					expect_route_entry[j].gate, 16) == 0) {
				found = true;
				unvisited_index.erase(it);
				break;
			} else {
				it++;
			}
		}

		if (!found) {
			std::cout
				<< "check_route_entry nhe mismatch: unexpected nhe "
				<< std::endl;
			print_nhe_t(dump_route_entry[i]);
			return false;
		}
	}

	return true;
}


bool RibUtils::check_rib_state(
	const std::vector<struct api_route_t> &dump_rib_state,
	const std::vector<struct api_route_t> &expect_rib_state)
{
	if (dump_rib_state.size() != expect_rib_state.size()) {
		std::cout << "dump_rib_state.size = " << dump_rib_state.size()
			  << ", expect_rib_state.size = "
			  << expect_rib_state.size() << std::endl;
		return false;
	}
	for (const auto &expect_rn : expect_rib_state) {
		bool found = false;
		for (const auto &dump_rn : dump_rib_state) {
			if (common_utils::is_prefix_t_euqal(
				    &dump_rn.prefix, &expect_rn.prefix)) {
				found = true;

				if (!check_route_entry(dump_rn.route_entry,
						       expect_rn.route_entry)) {
					return false;
				}

				break;
			}
		}

		if (!found) {
			std::cout
				<< "check_rib_state expected prefix not found: "
				<< common_utils::addr2str(
					   expect_rn.prefix.endpoint)
				<< "/" << expect_rn.prefix.prefixlen
				<< std::endl;
			return false;
		}
	}

	return true;
}

struct zapi_route
RibUtils::get_zapi_route_from_t(const struct api_route_t &route)
{
	struct zapi_route api = {};
	api.type = ZEBRA_ROUTE_BGP;
	api.message = ZAPI_MESSAGE_NEXTHOP | ZAPI_MESSAGE_SRTE;
	api.vrf_id = VPN_VRF_ID;

	// remote prefix
	char ipv4[INET_ADDRSTRLEN + 10];
	EXPECT_NE(
		inet_ntop(AF_INET, &route.prefix.endpoint, ipv4, sizeof(ipv4)),
		nullptr)
		<< "get_zapi_route_from_t fails";
	snprintf(ipv4 + strlen(ipv4), 10, "/%d", route.prefix.prefixlen);
	std::cout << "str2prefix " << ipv4 << std::endl;
	str2prefix(ipv4, &api.prefix);

	api.nexthop_num = route.route_entry.size();
	for (int i = 0; i < route.route_entry.size(); i++) {
		const struct nhe_t &nh = route.route_entry[i];
		api.nexthops[i].type = NEXTHOP_TYPE_IPV6_SEGMENTLIST;
		api.nexthops[i].srte_color = nh.color;
		api.nexthops[i].srte_color_flag = 1;
		std::memcpy(&api.nexthops[i].gate.ipv6, nh.gate, 16);
		api.nexthops[i].flags = ZAPI_NEXTHOP_FLAG_SRTE;

		api.nexthops[i].vrf_id = VPN_VRF_ID;
	}
	api.safi = SAFI_UNICAST;

	return api;
}