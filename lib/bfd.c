/**
 * bfd.c: BFD handling routines
 *
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "thread.h"
#include "stream.h"
#include "vrf.h"
#include "zclient.h"
#include "table.h"
#include "vty.h"
#include "bfd.h"
#include "bfdd/bfd.h"

DEFINE_MTYPE_STATIC(LIB, BFD_INFO, "BFD info");
DEFINE_HOOK(bfd_state_change_hook, (char *bfd_name, int state,int remote_cbit),(bfd_name, state, remote_cbit));
DEFINE_HOOK(sbfd_state_change_hook, (char *bfd_name, int state, uint32_t my_discr),(bfd_name, state, my_discr));


/**
 * BFD protocol integration configuration.
 */

struct bfd_sessions_global {
	/**
	 * Global BFD session parameters list for (re)installation and update
	 * without code duplication among daemons.
	 */
	TAILQ_HEAD(bsplist, bfd_session_params) bsplist;

	/** Pointer to FRR's event manager. */
	struct thread_master *tm;
	/** Pointer to zebra client data structure. */
	struct zclient *zc;

	/** Debugging state. */
	bool debugging;
	/** Is shutting down? */
	bool shutting_down;
};

/** Global configuration variable. */
static struct bfd_sessions_global bsglobal;

/** Global empty address for IPv4/IPv6. */
static const struct in6_addr i6a_zero;

/*
 * bfd_get_peer_info - Extract the Peer information for which the BFD session
 *                     went down from the message sent from Zebra to clients.
 */
static struct interface *bfd_get_peer_info(struct stream *s, struct prefix *dp,
					   struct prefix *sp, int *status, int *remote_cbit,
					   uint32_t *srte_color, uint32_t *my_discr, char *seglist_name,
					   vrf_id_t vrf_id, char *bfd_name, uint32_t *bfd_mode)
{
	unsigned int ifindex;
	struct interface *ifp = NULL;
	int plen;
	int local_remote_cbit;
	uint32_t color,bfdmode;
	uint8_t seglist_name_len;
	uint8_t bfd_name_len = 0;
	uint32_t discr = 0;

	/*
	 * If the ifindex lookup fails the
	 * rest of the data in the stream is
	 * not read.  All examples of this function
	 * call immediately use the dp->family which
	 * is not good.  Ensure we are not using
	 * random data
	 */
	memset(dp, 0, sizeof(*dp));
	memset(sp, 0, sizeof(*sp));

	/* Get interface index. */
	STREAM_GETL(s, ifindex);

	/* Lookup index. */
	if (ifindex != 0) {
		ifp = if_lookup_by_index(ifindex, vrf_id);
		if (ifp == NULL) {
			if (bsglobal.debugging)
				zlog_debug(
					"%s: Can't find interface by ifindex: %d ",
					__func__, ifindex);
			return NULL;
		}
	}

	/* Fetch destination address. */
	STREAM_GETC(s, dp->family);

	plen = prefix_blen(dp);
	STREAM_GET(&dp->u.prefix, s, plen);
	STREAM_GETC(s, dp->prefixlen);

	/* Get BFD status. */
	STREAM_GETL(s, (*status));

	STREAM_GETC(s, sp->family);

	plen = prefix_blen(sp);
	STREAM_GET(&sp->u.prefix, s, plen);
	STREAM_GETC(s, sp->prefixlen);

	STREAM_GETC(s, local_remote_cbit);
	if (remote_cbit)
		*remote_cbit = local_remote_cbit;

	STREAM_GETC(s, bfd_name_len);
	if(bfd_name_len) {
		STREAM_GET(bfd_name, s, bfd_name_len);
		*(bfd_name+bfd_name_len) = 0;
	}

	STREAM_GETL(s, bfdmode);
	*bfd_mode = bfdmode;

    /*support sbfd*/
	STREAM_GETL(s, color);
	*srte_color = color;
	STREAM_GETL(s, discr);
	*my_discr = discr;
    
	STREAM_GETC(s, seglist_name_len);
	if (seglist_name_len > 0 && seglist_name_len < 64)
	{
        STREAM_GET(seglist_name, s, seglist_name_len);
		seglist_name[seglist_name_len] = 0;
	}

	return ifp;

stream_failure:
	/*
	 * Clean dp and sp because caller
	 * will immediately check them valid or not
	 */
	memset(dp, 0, sizeof(*dp));
	memset(sp, 0, sizeof(*sp));
	return NULL;
}

/*
 * bfd_get_status_str - Convert BFD status to a display string.
 */
const char *bfd_get_status_str(int status)
{
	switch (status) {
	case BFD_STATUS_DOWN:
		return "Down";
	case BFD_STATUS_UP:
		return "Up";
	case BFD_STATUS_ADMIN_DOWN:
		return "Admin Down";
	case BFD_STATUS_DEL:
		return "Del";
	case BFD_STATUS_UNKNOWN:
	default:
		return "Unknown";
	}
}

/*
 * bfd_last_update - Calculate the last BFD update time and convert it
 *                   into a dd:hh:mm:ss display format.
 */
static void bfd_last_update(time_t last_update, char *buf, size_t len)
{
	time_t curr;
	time_t diff;
	struct tm tm;
	struct timeval tv;

	/* If no BFD status update has ever been received, print `never'. */
	if (last_update == 0) {
		snprintf(buf, len, "never");
		return;
	}

	/* Get current time. */
	monotime(&tv);
	curr = tv.tv_sec;
	diff = curr - last_update;
	gmtime_r(&diff, &tm);

	snprintf(buf, len, "%d:%02d:%02d:%02d", tm.tm_yday, tm.tm_hour,
		 tm.tm_min, tm.tm_sec);
}

/*
 * bfd_client_sendmsg - Format and send a client register
 *                    command to Zebra to be forwarded to BFD
 */
void bfd_client_sendmsg(struct zclient *zclient, int command,
			vrf_id_t vrf_id)
{
	struct stream *s;
	enum zclient_send_status ret;

	/* Check socket. */
	if (!zclient || zclient->sock < 0) {
		if (bsglobal.debugging)
			zlog_debug(
				"%s: Can't send BFD client register, Zebra client not established",
				__func__);
		return;
	}

	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, command, vrf_id);

	stream_putl(s, getpid());

	stream_putw_at(s, 0, stream_get_endp(s));

	ret = zclient_send_message(zclient);

	if (ret == ZCLIENT_SEND_FAILURE) {
		if (bsglobal.debugging)
			zlog_debug(
				"%s:  %ld: zclient_send_message() failed",
				__func__, (long)getpid());
		return;
	}

	return;
}

int zclient_bfd_command(struct zclient *zc, struct bfd_session_arg *args)
{
	struct stream *s;
	size_t addrlen;
	int len;

	/* Individual reg/dereg messages are suppressed during shutdown. */
	if (bsglobal.shutting_down) {
		if (bsglobal.debugging)
			zlog_debug(
				"%s: Suppressing BFD peer reg/dereg messages",
				__func__);
		return -1;
	}

	/* Check socket. */
	if (!zc || zc->sock < 0) {
		if (bsglobal.debugging)
			zlog_debug("%s: zclient unavailable", __func__);
		return -1;
	}

	s = zc->obuf;
	stream_reset(s);

	/* Create new message. */
	zclient_create_header(s, args->command, args->vrf_id);
	stream_putl(s, getpid());

	stream_putc(s, args->bfd_name[0] ? strlen(args->bfd_name) : 0);
	if (args->bfd_name[0])
			stream_put(s, args->bfd_name, strlen(args->bfd_name));

	/* Encode destination address. */
	stream_putw(s, args->family);
	addrlen = (args->family == AF_INET) ? sizeof(struct in_addr)
					    : sizeof(struct in6_addr);
	stream_put(s, &args->dst, addrlen);

	/*
	 * For more BFD integration protocol details, see function
	 * `_ptm_msg_read` in `bfdd/ptm_adapter.c`.
	 */
#if HAVE_BFDD > 0
	/* Session timers. */
	stream_putl(s, args->min_rx);
	stream_putl(s, args->min_tx);
	stream_putc(s, args->detection_multiplier);

	/* Is multi hop? */
	stream_putc(s, args->mhop != 0);

	/* Source address. */
	stream_putw(s, args->family);
	stream_put(s, &args->src, addrlen);

	/* Send the expected hops. */
	stream_putc(s, args->hops);

	/* Send interface name if any. */
	if (args->mhop) {
		/* Don't send interface. */
		stream_putc(s, 0);
		if (bsglobal.debugging && args->ifnamelen)
			zlog_debug("%s: multi hop is configured, not sending interface",
				   __func__);
	} else {
		stream_putc(s, args->ifnamelen);
		if (args->ifnamelen)
			stream_put(s, args->ifname, args->ifnamelen);
	}

	/* Send the C bit indicator. */
	stream_putc(s, args->cbit);

	/* Send profile name if any. */
	stream_putc(s, args->profilelen);
	if (args->profilelen)
		stream_put(s, args->profile, args->profilelen);

	if (args->command == ZEBRA_SBFD_DEST_REGISTER
	    || args->command == ZEBRA_SBFD_DEST_UPDATE) {
		stream_putc(s, args->is_sbfd_echo); // is sbfd echo
		stream_putl(s, args->sr_color);  // color
		addrlen = sizeof(struct in6_addr);
		stream_put(s, &args->sr_endpoint, addrlen); // endpoint
		/*sbfd remote discr ,if is sbfd echo discr == 0*/
        stream_putl(s, args->sbfd_remote_discr);
		// sidlist name
		len = strlen(args->seglist_name);
		stream_putc(s, len);
		stream_put(s, args->seglist_name, len);
        stream_putc(s, args->seglist_seg_num);
		int i;
		for(i=0; i < args->seglist_seg_num; i++)
		{
            stream_put(s, &args->seglist[i], addrlen);
		}
	}
	else if (args->command == ZEBRA_SBFD_DEST_DEREGISTER)
	{
		stream_putc(s, args->is_sbfd_echo); // is sbfd echo
		stream_putl(s, args->sr_color);  // color
		addrlen = sizeof(struct in6_addr);
		stream_put(s, &args->sr_endpoint, addrlen); // endpoint
		/*sbfd remote discr ,if is sbfd echo discr == 0*/
        stream_putl(s, args->sbfd_remote_discr);
		// sidlist name
		len = strlen(args->seglist_name);
		stream_putc(s, len);
		stream_put(s, args->seglist_name, len);		
	}

#else /* PTM BFD */
	/* Encode timers if this is a registration message. */
	if (args->command != ZEBRA_BFD_DEST_DEREGISTER) {
		stream_putl(s, args->min_rx);
		stream_putl(s, args->min_tx);
		stream_putc(s, args->detection_multiplier);
	}

	if (args->mhop) {
		/* Multi hop indicator. */
		stream_putc(s, 1);

		/* Multi hop always sends the source address. */
		stream_putw(s, args->family);
		stream_put(s, &args->src, addrlen);

		/* Send the expected hops. */
		stream_putc(s, args->hops);
	} else {
		/* Multi hop indicator. */
		stream_putc(s, 0);

		/* Single hop only sends the source address when IPv6. */
		if (args->family == AF_INET6) {
			stream_putw(s, args->family);
			stream_put(s, &args->src, addrlen);
		}

		/* Send interface name if any. */
		stream_putc(s, args->ifnamelen);
		if (args->ifnamelen)
			stream_put(s, args->ifname, args->ifnamelen);
	}

	/* Send the C bit indicator. */
	stream_putc(s, args->cbit);
#endif /* HAVE_BFDD */

	/* Finish the message by writing the size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	/* Send message to zebra. */
	if (zclient_send_message(zc) == ZCLIENT_SEND_FAILURE) {
		if (bsglobal.debugging)
			zlog_debug("%s: zclient_send_message failed", __func__);
		return -1;
	}

	return 0;
}

struct bfd_session_params *bfd_sess_new(bsp_status_update updatecb, void *arg)
{
	struct bfd_session_params *bsp;

	bsp = XCALLOC(MTYPE_BFD_INFO, sizeof(*bsp));

	/* Save application data. */
	bsp->updatecb = updatecb;
	bsp->arg = arg;

	/* Set defaults. */
	bsp->args.detection_multiplier = BFD_DEF_DETECT_MULT;
	bsp->args.hops = 1;
	bsp->args.min_rx = BFD_DEF_MIN_RX;
	bsp->args.min_tx = BFD_DEF_MIN_TX;
	bsp->args.vrf_id = VRF_DEFAULT;

	/* Register in global list. */
	TAILQ_INSERT_TAIL(&bsglobal.bsplist, bsp, entry);

	return bsp;
}

static bool _bfd_sess_valid(const struct bfd_session_params *bsp)
{
	/* Peer/local address not configured. */
	if (bsp->args.family == 0)
		return false;

	/* Address configured but invalid. */
	if (bsp->args.family != AF_INET && bsp->args.family != AF_INET6) {
		if (bsglobal.debugging)
			zlog_debug("%s: invalid session family: %d", __func__,
				   bsp->args.family);
		return false;
	}

	/* Invalid address. */
	if (memcmp(&bsp->args.dst, &i6a_zero, sizeof(i6a_zero)) == 0) {
		if (bsglobal.debugging) {
			if (bsp->args.family == AF_INET)
				zlog_debug("%s: invalid address: %pI4",
					   __func__,
					   (struct in_addr *)&bsp->args.dst);
			else
				zlog_debug("%s: invalid address: %pI6",
					   __func__, &bsp->args.dst);
		}
		return false;
	}

	/* Multi hop requires local address. */
	if (bsp->args.mhop
	    && memcmp(&i6a_zero, &bsp->args.src, sizeof(i6a_zero)) == 0) {
		if (bsglobal.debugging)
			zlog_debug(
				"%s: multi hop but no local address provided",
				__func__);
		return false;
	}

	/* Check VRF ID. */
	if (bsp->args.vrf_id == VRF_UNKNOWN) {
		if (bsglobal.debugging)
			zlog_debug("%s: asked for unknown VRF", __func__);
		return false;
	}

	return true;
}

static int _bfd_sess_send(struct thread *t)
{
	struct bfd_session_params *bsp = THREAD_ARG(t);
	int rv;

	/* Validate configuration before trying to send bogus data. */
	if (!_bfd_sess_valid(bsp))
		return 0;

	if (bsp->lastev == BSE_INSTALL) {
		bsp->args.command = bsp->installed ? ZEBRA_BFD_DEST_UPDATE
						   : ZEBRA_BFD_DEST_REGISTER;
	} else
		bsp->args.command = ZEBRA_BFD_DEST_DEREGISTER;

	/* If not installed and asked for uninstall, do nothing. */
	if (!bsp->installed && bsp->args.command == ZEBRA_BFD_DEST_DEREGISTER)
		return 0;

	rv = zclient_bfd_command(bsglobal.zc, &bsp->args);
	/* Command was sent successfully. */
	if (rv == 0) {
		/* Update installation status. */
		if (bsp->args.command == ZEBRA_BFD_DEST_DEREGISTER)
			bsp->installed = false;
		else if (bsp->args.command == ZEBRA_BFD_DEST_REGISTER)
			bsp->installed = true;
	} else {
		struct ipaddr src, dst;

		src.ipa_type = bsp->args.family;
		src.ipaddr_v6 = bsp->args.src;
		dst.ipa_type = bsp->args.family;
		dst.ipaddr_v6 = bsp->args.dst;

		zlog_err(
			"%s: BFD session %pIA -> %pIA interface %s VRF %s(%u) was not %s",
			__func__, &src, &dst,
			bsp->args.ifnamelen ? bsp->args.ifname : "*",
			vrf_id_to_name(bsp->args.vrf_id), bsp->args.vrf_id,
			bsp->lastev == BSE_INSTALL ? "installed"
						   : "uninstalled");
	}

	return 0;
}

static int _sbfd_sess_send(struct thread *t)
{
	struct bfd_session_params *bsp = THREAD_ARG(t);
	int rv;

	/* Validate configuration before trying to send bogus data. */
	if (!_bfd_sess_valid(bsp))
		return 0;

	if (bsp->lastev == BSE_INSTALL) {
		bsp->args.command = bsp->installed ? ZEBRA_SBFD_DEST_UPDATE
						   : ZEBRA_SBFD_DEST_REGISTER;
	} else
		bsp->args.command = ZEBRA_SBFD_DEST_DEREGISTER;

	/* If not installed and asked for uninstall, do nothing. */
	if (!bsp->installed && bsp->args.command == ZEBRA_SBFD_DEST_DEREGISTER)
		return 0;

	rv = zclient_bfd_command(bsglobal.zc, &bsp->args);
	/* Command was sent successfully. */
	if (rv == 0) {
		/* Update installation status. */
		if (bsp->args.command == ZEBRA_SBFD_DEST_DEREGISTER)
			bsp->installed = false;
		else if (bsp->args.command == ZEBRA_SBFD_DEST_REGISTER)
			bsp->installed = true;
	} else {
		struct ipaddr src, dst;

		src.ipa_type = bsp->args.family;
		src.ipaddr_v6 = bsp->args.src;
		dst.ipa_type = bsp->args.family;
		dst.ipaddr_v6 = bsp->args.dst;

		zlog_err(
			"%s: SBFD session %pIA -> %pIA interface %s VRF %s(%u) was not %s",
			__func__, &src, &dst,
			bsp->args.ifnamelen ? bsp->args.ifname : "*",
			vrf_id_to_name(bsp->args.vrf_id), bsp->args.vrf_id,
			bsp->lastev == BSE_INSTALL ? "installed"
						   : "uninstalled");
	}

	return 0;
}

static void _bfd_sess_remove(struct bfd_session_params *bsp)
{
	/* Cancel any pending installation request. */
	THREAD_OFF(bsp->installev);

	/* Not installed, nothing to do. */
	if (!bsp->installed)
		return;

	/* Send request to remove any session. */
	bsp->lastev = BSE_UNINSTALL;
	thread_execute(bsglobal.tm, _bfd_sess_send, bsp, 0);
}

static void _sbfd_sess_remove(struct bfd_session_params *bsp)
{

	/* Cancel any pending installation request. */
	THREAD_OFF(bsp->installev);

	/* Not installed, nothing to do. */
	if (!bsp->installed)
		return;

	/* Send request to remove any session. */
	bsp->lastev = BSE_UNINSTALL;
	thread_execute(bsglobal.tm, _sbfd_sess_send, bsp, 0);
}

void bfd_sess_free(struct bfd_session_params **bsp)
{
	if (*bsp == NULL)
		return;

	/* Remove any installed session. */
	_bfd_sess_remove(*bsp);

	/* Remove from global list. */
	TAILQ_REMOVE(&bsglobal.bsplist, (*bsp), entry);

	/* Free the memory and point to NULL. */
	XFREE(MTYPE_BFD_INFO, (*bsp));
}

void sbfd_sess_free(struct bfd_session_params **bsp)
{
	if (*bsp == NULL)
		return;

	/* Remove any installed session. */
	_sbfd_sess_remove(*bsp);

	/* Remove from global list. */
	TAILQ_REMOVE(&bsglobal.bsplist, (*bsp), entry);

	/* Free the memory and point to NULL. */
	XFREE(MTYPE_BFD_INFO, (*bsp));
}

static bool bfd_sess_address_changed(const struct bfd_session_params *bsp,
				     uint32_t family,
				     const struct in6_addr *src,
				     const struct in6_addr *dst)
{
	size_t addrlen;

	if (bsp->args.family != family)
		return true;

	addrlen = (family == AF_INET) ? sizeof(struct in_addr)
				      : sizeof(struct in6_addr);
	if ((src == NULL && memcmp(&bsp->args.src, &i6a_zero, addrlen))
	    || (src && memcmp(src, &bsp->args.src, addrlen))
	    || memcmp(dst, &bsp->args.dst, addrlen))
		return true;

	return false;
}

void bfd_sess_set_ipv4_addrs(struct bfd_session_params *bsp,
			     const struct in_addr *src,
			     const struct in_addr *dst)
{
	if (!bfd_sess_address_changed(bsp, AF_INET, (struct in6_addr *)src,
				      (struct in6_addr *)dst))
		return;

	/* If already installed, remove the old setting. */
	_bfd_sess_remove(bsp);

	bsp->args.family = AF_INET;

	/* Clean memory, set zero value and avoid static analyser warnings. */
	memset(&bsp->args.src, 0, sizeof(bsp->args.src));
	memset(&bsp->args.dst, 0, sizeof(bsp->args.dst));

	/* Copy the equivalent of IPv4 to arguments structure. */
	if (src)
		memcpy(&bsp->args.src, src, sizeof(struct in_addr));

	assert(dst);
	memcpy(&bsp->args.dst, dst, sizeof(struct in_addr));
}

void bfd_sess_set_ipv6_addrs(struct bfd_session_params *bsp,
			     const struct in6_addr *src,
			     const struct in6_addr *dst)
{
	if (!bfd_sess_address_changed(bsp, AF_INET6, src, dst))
		return;

	/* If already installed, remove the old setting. */
	_bfd_sess_remove(bsp);

	bsp->args.family = AF_INET6;

	/* Clean memory, set zero value and avoid static analyser warnings. */
	memset(&bsp->args.src, 0, sizeof(bsp->args.src));

	if (src)
		bsp->args.src = *src;

	assert(dst);
	bsp->args.dst = *dst;
}

void bfd_sess_set_interface(struct bfd_session_params *bsp, const char *ifname)
{
	if ((ifname == NULL && bsp->args.ifnamelen == 0)
	    || (ifname && strcmp(bsp->args.ifname, ifname) == 0))
		return;

	/* If already installed, remove the old setting. */
	_bfd_sess_remove(bsp);

	if (ifname == NULL) {
		bsp->args.ifname[0] = 0;
		bsp->args.ifnamelen = 0;
		return;
	}

	if (strlcpy(bsp->args.ifname, ifname, sizeof(bsp->args.ifname))
	    > sizeof(bsp->args.ifname))
		zlog_warn("%s: interface name truncated: %s", __func__, ifname);

	bsp->args.ifnamelen = strlen(bsp->args.ifname);
}

void bfd_sess_set_profile(struct bfd_session_params *bsp, const char *profile)
{
	if (profile == NULL) {
		bsp->args.profile[0] = 0;
		bsp->args.profilelen = 0;
		return;
	}

	if (strlcpy(bsp->args.profile, profile, sizeof(bsp->args.profile))
	    > sizeof(bsp->args.profile))
		zlog_warn("%s: profile name truncated: %s", __func__, profile);

	bsp->args.profilelen = strlen(bsp->args.profile);
}

void bfd_sess_set_vrf(struct bfd_session_params *bsp, vrf_id_t vrf_id)
{
	if (bsp->args.vrf_id == vrf_id)
		return;

	/* If already installed, remove the old setting. */
	_bfd_sess_remove(bsp);

	bsp->args.vrf_id = vrf_id;
}

void bfd_sess_set_hop_count(struct bfd_session_params *bsp, uint8_t hops)
{
	if (bsp->args.hops == hops)
		return;

	/* If already installed, remove the old setting. */
	_bfd_sess_remove(bsp);

	bsp->args.hops = hops;
	bsp->args.mhop = (hops > 1);
}


void bfd_sess_set_cbit(struct bfd_session_params *bsp, bool enable)
{
	bsp->args.cbit = enable;
}

void bfd_sess_set_timers(struct bfd_session_params *bsp,
			 uint8_t detection_multiplier, uint32_t min_rx,
			 uint32_t min_tx)
{
	bsp->args.detection_multiplier = detection_multiplier;
	bsp->args.min_rx = min_rx;
	bsp->args.min_tx = min_tx;
}

void sbfd_sess_set_srpolicy_info(struct bfd_session_params *bsp, uint32_t color, struct in6_addr* endpoint)
{
	memcpy(&bsp->args.sr_endpoint, endpoint, sizeof(struct in6_addr));
	bsp->args.sr_color = color;
}

struct in6_addr* sbfd_sess_get_srpolicy_endpoint(struct bfd_session_params *bsp)
{
	return &(bsp->args.sr_endpoint);
}

uint32_t sbfd_sess_get_srpolicy_color(struct bfd_session_params *bsp)
{
	return bsp->args.sr_color;
}

void sbfd_sess_set_sbfd_echo(struct bfd_session_params *bsp, uint32_t sbfd_echo_flag)
{
	bsp->args.is_sbfd_echo = sbfd_echo_flag;
}

void sbfd_sess_set_segments(struct bfd_session_params *bsp, char* seglist_name, uint8_t segnum, struct in6_addr* seglist)
{
	if (segnum == 0)
		return;
    
	uint32_t i = 0;
	
    while (i < segnum && seglist)
	{
		/* code */
		
		memcpy(&bsp->args.seglist[i], seglist, sizeof(struct in6_addr));
		seglist++;
		i++;
	}

	bsp->args.seglist_seg_num = i;

	memcpy(bsp->args.seglist_name , seglist_name, 64);
}

void sbfd_sess_set_segment_list_name(struct bfd_session_params *bsp, char* seglist_name)
{
	memcpy(bsp->args.seglist_name , seglist_name, 64);
}

void bfd_sess_set_remote_discr(struct bfd_session_params *bsp, uint32_t discr)
{
	bsp->args.sbfd_remote_discr = discr;
}

void bfd_sess_install(struct bfd_session_params *bsp)
{
	bsp->lastev = BSE_INSTALL;
	thread_add_event(bsglobal.tm, _bfd_sess_send, bsp, 0, &bsp->installev);
}

void sbfd_sess_install(struct bfd_session_params *bsp)
{
	bsp->lastev = BSE_INSTALL;
	thread_add_event(bsglobal.tm, _sbfd_sess_send, bsp, 0, &bsp->installev);
}

void bfd_sess_uninstall(struct bfd_session_params *bsp)
{
	bsp->lastev = BSE_UNINSTALL;
	thread_add_event(bsglobal.tm, _bfd_sess_send, bsp, 0, &bsp->installev);
}

void sbfd_sess_uninstall(struct bfd_session_params *bsp)
{
	bsp->lastev = BSE_UNINSTALL;
	thread_add_event(bsglobal.tm, _sbfd_sess_send, bsp, 0, &bsp->installev);
}

enum bfd_session_state bfd_sess_status(const struct bfd_session_params *bsp)
{
	return bsp->bss.state;
}

uint8_t bfd_sess_hop_count(const struct bfd_session_params *bsp)
{
	return bsp->args.hops;
}

const char *bfd_sess_profile(const struct bfd_session_params *bsp)
{
	return bsp->args.profilelen ? bsp->args.profile : NULL;
}

void bfd_sess_addresses(const struct bfd_session_params *bsp, int *family,
			struct in6_addr *src, struct in6_addr *dst)
{
	*family = bsp->args.family;
	if (src)
		*src = bsp->args.src;
	if (dst)
		*dst = bsp->args.dst;
}

const char *bfd_sess_interface(const struct bfd_session_params *bsp)
{
	if (bsp->args.ifnamelen)
		return bsp->args.ifname;

	return NULL;
}

const char *bfd_sess_vrf(const struct bfd_session_params *bsp)
{
	return vrf_id_to_name(bsp->args.vrf_id);
}

vrf_id_t bfd_sess_vrf_id(const struct bfd_session_params *bsp)
{
	return bsp->args.vrf_id;
}

bool bfd_sess_cbit(const struct bfd_session_params *bsp)
{
	return bsp->args.cbit;
}

void bfd_sess_timers(const struct bfd_session_params *bsp,
		     uint8_t *detection_multiplier, uint32_t *min_rx,
		     uint32_t *min_tx)
{
	*detection_multiplier = bsp->args.detection_multiplier;
	*min_rx = bsp->args.min_rx;
	*min_tx = bsp->args.min_tx;
}

void bfd_sess_show(struct vty *vty, struct json_object *json,
		   struct bfd_session_params *bsp)
{
	json_object *json_bfd = NULL;
	char time_buf[64];

	if (!bsp)
		return;

	/* Show type. */
	if (json) {
		json_bfd = json_object_new_object();
		if (bsp->args.mhop)
			json_object_string_add(json_bfd, "type", "multi hop");
		else
			json_object_string_add(json_bfd, "type", "single hop");
	} else
		vty_out(vty, "  BFD: Type: %s\n",
			bsp->args.mhop ? "multi hop" : "single hop");

	/* Show configuration. */
	if (json) {
		json_object_int_add(json_bfd, "detectMultiplier",
				    bsp->args.detection_multiplier);
		json_object_int_add(json_bfd, "rxMinInterval",
				    bsp->args.min_rx);
		json_object_int_add(json_bfd, "txMinInterval",
				    bsp->args.min_tx);
	} else {
		vty_out(vty,
			"  Detect Multiplier: %d, Min Rx interval: %d, Min Tx interval: %d\n",
			bsp->args.detection_multiplier, bsp->args.min_rx,
			bsp->args.min_tx);
	}

	bfd_last_update(bsp->bss.last_event, time_buf, sizeof(time_buf));
	if (json) {
		json_object_string_add(json_bfd, "status",
				       bfd_get_status_str(bsp->bss.state));
		json_object_string_add(json_bfd, "lastUpdate", time_buf);
	} else
		vty_out(vty, "  Status: %s, Last update: %s\n",
			bfd_get_status_str(bsp->bss.state), time_buf);

	if (json)
		json_object_object_add(json, "peerBfdInfo", json_bfd);
	else
		vty_out(vty, "\n");
}

/*
 * Zebra communication related.
 */

/**
 * Callback for reinstallation of all registered BFD sessions.
 *
 * Use this as `zclient` `bfd_dest_replay` callback.
 */
int zclient_bfd_session_replay(ZAPI_CALLBACK_ARGS)
{
	struct bfd_session_params *bsp;

	if (!zclient->bfd_integration)
		return 0;

	/* Do nothing when shutting down. */
	if (bsglobal.shutting_down)
		return 0;

	if (bsglobal.debugging)
		zlog_debug("%s: sending all sessions registered", __func__);

	/* Send the client registration */
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER, vrf_id);

	/* Replay all activated peers. */
	TAILQ_FOREACH (bsp, &bsglobal.bsplist, entry) {
		/* Skip not installed sessions. */
		if (!bsp->installed)
			continue;

		/* We are reconnecting, so we must send installation. */
		bsp->installed = false;

		/* Cancel any pending installation request. */
		THREAD_OFF(bsp->installev);

		/* Ask for installation. */
		bsp->lastev = BSE_INSTALL;
		thread_execute(bsglobal.tm, _bfd_sess_send, bsp, 0);
	}

	return 0;
}

int zclient_bfd_session_update(ZAPI_CALLBACK_ARGS)
{
	struct bfd_session_params *bsp, *bspn;
	size_t sessions_updated = 0;
	struct interface *ifp;
	int remote_cbit = false;
	int state = BFD_STATUS_UNKNOWN;
	time_t now;
	size_t addrlen;
	struct prefix dp;
	struct prefix sp;
	char ifstr[128], cbitstr[32];
	uint32_t srte_color = 0;
	uint32_t bfd_mode = 0;
	char seglist_name[64] = {0};
    char bfd_name[BFD_NAME_SIZE+1] = {0};
	uint32_t my_discr = 0;

	if (!zclient->bfd_integration)
		return 0;

	/* Do nothing when shutting down. */
	if (bsglobal.shutting_down)
		return 0;

	ifp = bfd_get_peer_info(zclient->ibuf, &dp, &sp, &state, &remote_cbit,  &srte_color,
		&my_discr, seglist_name, vrf_id, bfd_name, &bfd_mode);
	/*
	 * When interface lookup fails or an invalid stream is read, we must
	 * not proceed otherwise it will trigger an assertion while checking
	 * family type below.
	 */
	if (dp.family == 0 || sp.family == 0)
		return 0;

	if (bsglobal.debugging) {
		ifstr[0] = 0;
		if (ifp)
			snprintf(ifstr, sizeof(ifstr), " (interface %s)",
				 ifp->name);

		snprintf(cbitstr, sizeof(cbitstr), " (CPI bit %s)",
			 remote_cbit ? "yes" : "no");

		zlog_debug("%s: %pFX -> %pFX%s VRF %s(%u)%s: %s", __func__, &sp,
			   &dp, ifstr, vrf_id_to_name(vrf_id), vrf_id, cbitstr,
			   bfd_get_status_str(state));
	}

	switch (dp.family) {
	case AF_INET:
		addrlen = sizeof(struct in_addr);
		break;
	case AF_INET6:
		addrlen = sizeof(struct in6_addr);
		break;

	default:
		/* Unexpected value. */
		assert(0);
		break;
	}

	/* Cache current time to avoid multiple monotime clock calls. */
	now = monotime(NULL);
    
	if (bfd_name[0])
	{
		if ((bfd_mode == BFD_MODE_TYPE_SBFD_ECHO) || (bfd_mode == BFD_MODE_TYPE_SBFD))
		{
			hook_call(sbfd_state_change_hook, bfd_name, state, my_discr);
			if (bsglobal.debugging)
				zlog_debug("%s:   sessions updated: %s(%u)", __func__,  bfd_name, my_discr);
		}
		else
		{
			hook_call(bfd_state_change_hook, bfd_name, state, remote_cbit);
			if (bsglobal.debugging)
				zlog_debug("%s:   sessions updated: %s", __func__,  bfd_name);
		}

		return 0;
	}
	/* Notify all matching sessions about update. */
	TAILQ_FOREACH_SAFE (bsp, &bsglobal.bsplist, entry, bspn) {
		/* Skip not installed entries. */
		if (!bsp->installed)
			continue;
		/* Skip different VRFs. */
		if (bsp->args.vrf_id != vrf_id)
			continue;
		/* Skip different families. */
		if (bsp->args.family != dp.family)
			continue;
		/* Skip different interface. */
		if (bsp->args.ifnamelen && ifp
		    && strcmp(bsp->args.ifname, ifp->name) != 0)
			continue;
		/* Skip non matching destination addresses. */
		if (memcmp(&bsp->args.dst, &dp.u, addrlen) != 0)
			continue;
		/*
		 * Source comparison test:
		 * We will only compare source if BFD daemon provided the
		 * source address and the protocol set a source address in
		 * the configuration otherwise we'll just skip it.
		 */
		if (sp.family && memcmp(&bsp->args.src, &i6a_zero, addrlen) != 0
		    && memcmp(&sp.u, &i6a_zero, addrlen) != 0
		    && memcmp(&bsp->args.src, &sp.u, addrlen) != 0)
			continue;
        
		/*support sbfd*/
		if (bsp->args.sr_color != srte_color)
		    continue;
	    
		if (bsp->args.seglist_name[0] && seglist_name[0] 
		    && strcmp(bsp->args.seglist_name, seglist_name) != 0)
			continue;

		/* No session state change. */
		if ((int)bsp->bss.state == state)
			continue;

		bsp->bss.last_event = now;
		bsp->bss.previous_state = bsp->bss.state;
		bsp->bss.state = state;
		bsp->bss.remote_cbit = remote_cbit;
		bsp->updatecb(bsp, &bsp->bss, bsp->arg);
		sessions_updated++;
	}

	if (bsglobal.debugging)
		zlog_debug("%s:   sessions updated: %zu", __func__,
			   sessions_updated);

	return 0;
}

void bfd_protocol_integration_init(struct zclient *zc, struct thread_master *tm)
{
	/* Initialize data structure. */
	TAILQ_INIT(&bsglobal.bsplist);

	/* Copy pointers. */
	bsglobal.zc = zc;
	bsglobal.tm = tm;

	/* Enable BFD callbacks. */
	zc->bfd_integration = true;

	/* Send the client registration */
	bfd_client_sendmsg(zc, ZEBRA_BFD_CLIENT_REGISTER, VRF_DEFAULT);
}

void bfd_protocol_integration_set_debug(bool enable)
{
	bsglobal.debugging = enable;
}

void bfd_protocol_integration_set_shutdown(bool enable)
{
	bsglobal.shutting_down = enable;
}

bool bfd_protocol_integration_debug(void)
{
	return bsglobal.debugging;
}

bool bfd_protocol_integration_shutting_down(void)
{
	return bsglobal.shutting_down;
}

void bfd_name_register(struct bfd_session_params *bsp) {
	bsp->args.command = ZEBRA_BFD_DEST_REGISTER;
	zclient_bfd_command(bsglobal.zc, &bsp->args);
}
