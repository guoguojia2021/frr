//
// Created by mengqi.liu on 2/20/25.
//

#ifndef GTEST_ALIBGP_ZEBRA_UTILS_H
#define GTEST_ALIBGP_ZEBRA_UTILS_H

#include "lib/zclient.h"
#include "zebra.h"
#include "zebra/zapi_msg.h"

#include "test_model.h"


void setup_zebra_state(const struct zebra_state_t &initial_state,
		       zebra_vrf *zvrf, zserv *client);

void setup_global_env();
void setup_env();
void teardown_env();

void perform_action(const struct step_action_t &action, zserv *client,
		    zebra_vrf *zvrf);

#endif // GTEST_ALIBGP_ZEBRA_UTILS_H
