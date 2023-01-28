#include <zebra.h>

#include "lib/bitmap.h"
#include "jhash.h"


#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_zebra.h"


#define BGP_VRF_RANGE     10 * 1024

struct bgp_irt_node {
	/* RT */
	struct ecommunity_val rt;

	/* List of VRFs importing routes matching this RT. */
	struct list *vrfs;
};

unsigned int bgp_import_rt_hash_key_make(void *p);
bool bgp_import_rt_hash_cmp(const void *p1, const void *p2);
struct bgp_irt_node *bgp_import_rt_new(struct ecommunity_val *rt);
struct bgp_irt_node *bgp_lookup_import_rt(struct ecommunity_val *rt);
int bgp_is_vrf_present_in_irt(struct list *vrfs, struct bgp *bgp);
void bgp_map_vrf_to_its_rts(struct ecommunity *ecom, struct bgp *bgp);
void bgp_import_rt_free(struct bgp_irt_node *irt);
void bgp_unmap_vrf_to_its_rts(struct ecommunity *ecom, struct bgp *bgp);
void bgp_hash_irt_free(void *irt);


