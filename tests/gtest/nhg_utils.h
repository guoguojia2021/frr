//
// Created by lsn on 2024/12/2.
//

#ifndef NHG_UTILS_H
#define NHG_UTILS_H

#include "test_model.h"
#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"


class NHGUtils
{
      private:
	zebra_vrf *zvrf;

	zserv client;

      public:
	int init();

	void set_zvrf(zebra_vrf *zvrf);

	//	int add_nhg_info(std::vector<nhg_t> *nhgs);

	//	int register_rnh_from_nhg_t(struct nhg_t *nhg_t);

	static std::vector<struct nexthop_t>
	dump_nexthop_group(struct nexthop_group &nhg);

	static std::vector<struct nhg_t> dump_nhgs();

	static bool check_nhg_state(const std::vector<nhg_t> &expected_state,
				    const std::vector<nhg_t> &dump_state);

	static std::vector<struct api_route_t>
	gen_route_for_nhgs(const std::vector<struct nhg_t> &nhgs);
};

extern NHGUtils nhg_utils;

void enable_sidlist_nhg();
void reset_sidlist_nhg();


#endif // NHG_UTILS_H
