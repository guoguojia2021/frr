#ifndef GTEST_ALIBGP_NEXTHOP_UTILS_H
#define GTEST_ALIBGP_NEXTHOP_UTILS_H

#include "test_model.h"


class NexthopUtils
{
      public:
	static std::vector<struct nexthop_t>
	dump_nexthop_group(struct nexthop_group &nhg);

	static bool nexthop_match(const struct nexthop_t &exp_n,
				  const struct nexthop_t &dump_n);
	static bool nexthop_list_match(const std::vector<struct nexthop_t> &exp_nl,
				       const std::vector<struct nexthop_t> &dump_nl);
	static int height(const struct nexthop_t &n);
};


#endif // GTEST_ALIBGP_NEXTHOP_UTILS_H
