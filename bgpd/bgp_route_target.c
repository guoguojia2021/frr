#include "bgp_route_target.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"

/*
 * Make import route target hash key.
 */
unsigned int bgp_import_rt_hash_key_make(const void *p)
{
	struct bgp_irt_node *irt = p;
	char *pnt = irt->rt.val;

	return jhash(pnt, 8, 0xdeadbeef);
}

/*
 * Comparison function for import rt hash
 */
bool bgp_import_rt_hash_cmp(const void *p1, const void *p2)
{
	const struct bgp_irt_node *irt1 = p1;
	const struct bgp_irt_node *irt2 = p2;

	if (irt1 == NULL && irt2 == NULL)
		return 1;

	if (irt1 == NULL || irt2 == NULL)
		return 0;

	return (memcmp(irt1->rt.val, irt2->rt.val, ECOMMUNITY_SIZE) == 0);
}

/*
 * Create a new import_rt
 */
struct bgp_irt_node *bgp_import_rt_new(struct ecommunity_val *rt)
{
	struct bgp_irt_node *irt;

	irt = XCALLOC(MTYPE_ECOMMUNITY, sizeof(struct bgp_irt_node));
	if (!irt)
		return NULL;

	irt->rt = *rt;
	/* Add to hash */
	if (!hash_get(bm->vrf_import_rt_hash, irt, hash_alloc_intern)) {
		XFREE(MTYPE_ECOMMUNITY, irt);
		return NULL;
	}
	irt->vrfs = list_new();

	return irt;
}

struct bgp_irt_node *bgp_lookup_import_rt(struct ecommunity_val *rt)
{
	struct bgp_irt_node *irt;
	struct bgp_irt_node tmp;

	memset(&tmp, 0, sizeof(struct bgp_irt_node));
	memcpy(&tmp.rt, rt, ECOMMUNITY_SIZE);
	irt = hash_lookup(bm->vrf_import_rt_hash, &tmp);
	return irt;
}
/*
 * Is specified VRF present on the RT's list of "importing" VRFs?
 */
int bgp_is_vrf_present_in_irt(struct list *vrfs, struct bgp *bgp)
{
	struct listnode *node, *nnode;
	struct bgp *tmp_bgp;

	for (ALL_LIST_ELEMENTS(vrfs, node, nnode, tmp_bgp)) {
		if (tmp_bgp == bgp)
			return 1;
	}
	return 0;
}


void bgp_map_vrf_to_its_rts(struct ecommunity *ecom, struct bgp *bgp)
{
	int i;
	struct ecommunity_val eval;
	struct bgp_irt_node *irt;
	for (i = 0; i < ecom->size; ++i) {
		memcpy(&eval, (ecom->val + (i * ECOMMUNITY_SIZE)), ECOMMUNITY_SIZE);
		irt = bgp_lookup_import_rt(&eval);
		if (irt && irt->vrfs)
			if (bgp_is_vrf_present_in_irt(irt->vrfs, bgp))
				/* Already mapped. */
				continue;

		if (!irt) {
			irt = bgp_import_rt_new(&eval);
			if (!irt)
			{
				return;
			}
		}
		
		/* Add VRF_BGP to the hash list for this RT. */
		listnode_add(irt->vrfs, bgp);
	}
}

/*
* Free the import rt node
*/
void bgp_import_rt_free(struct bgp_irt_node *irt)
{
	list_delete(&irt->vrfs);
	hash_release(bm->vrf_import_rt_hash, irt);
	XFREE(MTYPE_ECOMMUNITY, irt);
}

void bgp_hash_irt_free(void *irt)
{
	struct bgp_irt_node *v_irt = (struct bgp_irt_node *)irt;
	list_delete(&v_irt->vrfs);
	XFREE(MTYPE_ECOMMUNITY, v_irt);
}

/*
 * Unmap the RTs.
 */
void bgp_unmap_vrf_to_its_rts(struct ecommunity *ecom, struct bgp *bgp)
{
	int i;
	struct ecommunity_val eval;
	struct bgp_irt_node *irt;

	for (i = 0; i < ecom->size; ++i) {
		memcpy(&eval, (ecom->val + (i * ECOMMUNITY_SIZE)), ECOMMUNITY_SIZE);

		irt = bgp_lookup_import_rt(&eval);
		if (irt){
			listnode_delete(irt->vrfs, bgp);
			if (!listnode_head(irt->vrfs)) {
				bgp_import_rt_free(irt);
			}
		}
	}
}

