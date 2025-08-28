#ifndef GTEST_PATHD_SEGMENT_UTILS_H
#define GTEST_PATHD_SEGMENT_UTILS_H

#include "test_model.h"


std::vector<struct segment_list_t> dump_segment_lists();
bool compare_segment_list(const struct segment_list_t &a,
			  const struct segment_list_t &b);

#endif // GTEST_PATHD_SEGMENT_UTILS_H
