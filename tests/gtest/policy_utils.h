//
// Created by lsn on 2024/12/2.
//

#ifndef POLICY_UTILS_H
#define POLICY_UTILS_H
#include <map>
#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "test_model.h"

class PolicyUtils
{
      private:
	zebra_vrf *zvrf;

	// Necessary for zread_route_add
	zserv client;

      public:
	int get_policy_from_case_policy_t(struct zapi_sr_policy *zp,
					  const struct policy_t *policy);

	int init();

	void set_zvrf(zebra_vrf *zvrf);

	zebra_vrf *get_mock_zvrf();

	zserv *get_mock_client();

	int
	add_policy_into_srte_table(const struct zebra_state_t &case_data);

	struct stream *fill_stream_with_policy(struct zapi_sr_policy *zp);

	int get_srv6_tunnel_from_case_srv6_tunnel_t(
		struct zapi_srv6te_tunnel *zt,
		const std::vector<srv6_sidlist_t> *sidlist);

	int get_input_policy_from_case_api_policy_t(
		struct zapi_sr_policy *zp,
		const struct api_policy_t *input_policy);

	static void dump_route_table(struct route_table *table,
			      struct srte_table_t &st);

	static bool check_srv6_tunnel(const struct policy_t &dumped,
			       const struct policy_t &expected);

	static bool check_polices(const struct srte_table_t &dump_table,
			   const struct srte_table_t &expected_table);
	static bool
	check_srte_states(const std::map<uint32_t, srte_table_t> &dump_srte_state,
			  const struct zebra_state_t &expected_state);
	void add_init_route(const struct zebra_state_t *initial_state,
			    const char *init_route);
};

extern PolicyUtils policy_utils;
void dump_srte_hash_bucket(struct hash_bucket *bucket, void *arg);

void free_srte_table_hash(struct hash_bucket *bucket, void *arg);

#endif // POLICY_UTILS_H
