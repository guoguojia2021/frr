#ifndef GTEST_MSG_UTILS_H
#define GTEST_MSG_UTILS_H

#include <vector>

#include "zebra/zserv.h"
#include "test_model.h"


std::vector<struct msg_t> dump_messages(struct zserv *client);

void print_msg_t(const struct msg_t &msg);

bool compare_msg_t(const struct msg_t &dump_msg,
		   const struct msg_t &expected_msg);

#endif // GTEST_MSG_UTILS_H
