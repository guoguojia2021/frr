//
// Created by mengqi.liu on 2/20/25.
//

#ifndef GTEST_ALIBGP_ZEBRA_UTILS_H
#define GTEST_ALIBGP_ZEBRA_UTILS_H

#include "lib/zclient.h"
#include "zebra.h"
#include "zebra/zapi_msg.h"

#include "test_model.h"


void setup_zebra_state(const struct zebra_state_t &initial_state);
bool compare_zebra_state(const struct zebra_state_t &expected_state);
bool compare_msg_fifo(const std::vector<struct msg_t> &expected_msg_fifo);

void setup_global_env();
void setup_env();
void teardown_env();

void perform_action(const struct step_action_t &action);

// Wrappers for tested APIs
void gtest_policy_set(const api_policy_t &policy);
void gtest_policy_del(const api_policy_t &policy);
void gtest_rnh_register(const api_rnh_t &rnh);
void gtest_rnh_unregister(const api_rnh_t &rnh);
void gtest_route_add(const api_route_t &route);
void gtest_route_del(const api_route_t &route);

#endif // GTEST_ALIBGP_ZEBRA_UTILS_H
