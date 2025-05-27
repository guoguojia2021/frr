/*
 * Main implementation file for interface to Forwarding Plane Manager.
 *
 * Copyright (C) 2012 by Open Source Routing.
 * Copyright (C) 2012 by Internet Systems Consortium, Inc. ("ISC")
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

#include "log.h"
#include "libfrr.h"
#include "stream.h"
#include "thread.h"
#include "network.h"
#include "command.h"
#include "version.h"
#include "jhash.h"

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_errors.h"

#include "bfd_fpm_private.h"
#include "bfd_fpm.h"
#include "bfd.h"
#include "buffer.h"
#include "lib_errors.h"

/*
 * Interval at which we attempt to connect to the FPM.
 */
#define BFPM_CONNECT_RETRY_IVL   5

/*
 * Sizes of outgoing and incoming stream buffers for writing/reading
 * FPM messages.
 */
#define BFPM_OBUF_SIZE (2 * 4096)
#define BFPM_IBUF_SIZE (4096)
#define BFDSYNCD_DEFAULT_IP              (htonl (INADDR_LOOPBACK))

/*
 * The maximum number of times the FPM socket write callback can call
 * 'write' before it yields.
 */
#define BFDSYNC_MAX_WRITES_PER_RUN 10

/*
 * States for the FPM state machine.
 */
typedef enum {

	/*
	 * In this state we are not yet ready to connect to the FPM. This
	 * can happen when this module is disabled, or if we're cleaning up
	 * after a connection has gone down.
	 */
	BFPM_STATE_IDLE,

	/*
	 * Ready to talk to the FPM and periodically trying to connect to
	 * it.
	 */
	BFPM_STATE_ACTIVE,

	/*
	 * In the middle of bringing up a TCP connection. Specifically,
	 * waiting for a connect() call to complete asynchronously.
	 */
	BFPM_STATE_CONNECTING,

	/*
	 * TCP connection to the FPM is up.
	 */
	BFPM_STATE_ESTABLISHED

} bfpm_state_t;

/*
 * Globals.
 */
typedef struct bfpm_glob_t_ {

	/*
	 * True if the FPM module has been enabled.
	 */
	int enabled;

	struct thread_master *master;
    
    bfpm_state_t state;

	in_addr_t fpm_server;
	/*
	 * Port on which the FPM is running.
	 */
	int fpm_port;

	/*
	 * Stream socket to the FPM.
	 */
	int sock;

	/*
	 * Buffers for messages to/from the FPM.
	 */
	/* Input/output buffer to the client. */
	pthread_mutex_t ibuf_mtx;
	struct stream_fifo *ibuf_fifo;
	/* Buffer of data waiting to be written to zebra. */
	struct buffer *waitbuf;

	struct stream *obuf;
	struct stream *ibuf;

	/*
	 * Threads for I/O.
	 */
	struct thread *t_connect;
	struct thread *t_write;
	struct thread *t_read;

	/*
	 * Thread to clean up after the TCP connection to the FPM goes down
	 * and the state that belongs to it.
	 */
	struct thread *t_conn_down;

	unsigned long connect_calls;
	time_t last_connect_call_time;

} bfpm_glob_t;

static bfpm_glob_t bfpm_glob_space;
static bfpm_glob_t *bfpm_g = &bfpm_glob_space;

static int bfpm_read_cb(struct thread *thread);
static int bfpm_write_cb(struct thread *thread);

static void bfpm_set_state(bfpm_state_t state, const char *reason);
static void bfpm_start_connect_timer(const char *reason);

static void _bfd_send_bfpm_srmsg(struct hash_bucket *hb, void *arg);

/*
 * zfpm_thread_should_yield
 */
static inline int bfpm_thread_should_yield(struct thread *t)
{
	return thread_should_yield(t);
}

/*
 * zfpm_state_to_str
 */
static const char *bfpm_state_to_str(bfpm_state_t state)
{
	switch (state) {

	case BFPM_STATE_IDLE:
		return "idle";

	case BFPM_STATE_ACTIVE:
		return "active";

	case BFPM_STATE_CONNECTING:
		return "connecting";

	case BFPM_STATE_ESTABLISHED:
		return "established";

	default:
		return "unknown";
	}
}

/*
 * zfpm_get_elapsed_time
 *
 * Returns the time elapsed (in seconds) since the given time.
 */
static time_t bfpm_get_elapsed_time(time_t reference)
{
	time_t now;

	now = monotime(NULL);

	if (now < reference) {
		assert(0);
		return 0;
	}

	return now - reference;
}

/*
 * zfpm_read_on
 */
static inline void bfpm_read_on(void)
{
	assert(!bfpm_g->t_read);
	assert(bfpm_g->sock >= 0);

	thread_add_read(bfpm_g->master, bfpm_read_cb, 0, bfpm_g->sock,
			&bfpm_g->t_read);
}

/*
 * zfpm_write_on
 */
static inline void bfpm_write_on(void)
{
	assert(!bfpm_g->t_write);
	assert(bfpm_g->sock >= 0);

	thread_add_write(bfpm_g->master, bfpm_write_cb, 0, bfpm_g->sock,
			 &bfpm_g->t_write);
}

/*
 * zfpm_read_off
 */
static inline void bfpm_read_off(void)
{
	THREAD_OFF(bfpm_g->t_read);
}

/*
 * zfpm_write_off
 */
static inline void bfpm_write_off(void)
{
	THREAD_OFF(bfpm_g->t_write);
}


/*
 * zfpm_connection_up
 *
 * Called when the connection to the FPM comes up.
 */
static void bfpm_connection_up(const char *detail)
{
	assert(bfpm_g->sock >= 0);
	bfpm_read_on();
	bfpm_write_on();
	bfpm_set_state(BFPM_STATE_ESTABLISHED, detail);

	bfpm_debug("Starting conn_up thread");

    /* send pending msg*/
	sbfd_discr_iterate(_bfd_send_bfpm_srmsg, NULL);
}

/*
 * zfpm_connect_check
 *
 * Check if an asynchronous connect() to the FPM is complete.
 */
static void bfpm_connect_check(void)
{
	int status;
	socklen_t slen;
	int ret;

	bfpm_read_off();
	bfpm_write_off();

	slen = sizeof(status);
	ret = getsockopt(bfpm_g->sock, SOL_SOCKET, SO_ERROR, (void *)&status,
			 &slen);

	if (ret >= 0 && status == 0) {
		bfpm_connection_up("async connect complete");
		return;
	}

	/*
	 * getsockopt() failed or indicated an error on the socket.
	 */
	close(bfpm_g->sock);
	bfpm_g->sock = -1;

	bfpm_start_connect_timer("getsockopt() after async connect failed");
	return;
}

/*
 * zfpm_conn_down_thread_cb
 *
 * Callback that is invoked to clean up state after the TCP connection
 * to the FPM goes down.
 */
static int bfpm_conn_down_thread_cb(struct thread *thread)
{

	assert(bfpm_g->state == BFPM_STATE_IDLE);

	/*
	 * Start the process of connecting to the FPM again.
	 */
	bfpm_start_connect_timer("cleanup complete");
	return 0;
}

/*
 * zfpm_connection_down
 *
 * Called when the connection to the FPM has gone down.
 */
static void bfpm_connection_down(const char *detail)
{
	if (!detail)
		detail = "unknown";

	assert(bfpm_g->state == BFPM_STATE_ESTABLISHED);

	zlog_info("connection to the FPM has gone down: %s", detail);

	bfpm_read_off();
	bfpm_write_off();

	stream_reset(bfpm_g->ibuf);
	stream_reset(bfpm_g->obuf);

	if (bfpm_g->sock >= 0) {
		close(bfpm_g->sock);
		bfpm_g->sock = -1;
	}

	/*
	 * Start thread to clean up state after the connection goes down.
	 */
	assert(!bfpm_g->t_conn_down);
	bfpm_debug("Starting conn_down thread");
	bfpm_g->t_conn_down = NULL;
	thread_add_timer_msec(bfpm_g->master, bfpm_conn_down_thread_cb, NULL, 0,
			      &bfpm_g->t_conn_down);
	bfpm_set_state(BFPM_STATE_IDLE, detail);
}

const char *bfd_status_translate(int status)
{
	switch (status) {
    case BFD_NOTIFY_UP:
        return "up";
    case BFD_NOTIFY_DOWN:
        return "down";
	default:
	    return "unknown";
    }
}

/*
 * zfpm_read_cb
 */
static int bfpm_read_cb(struct thread *thread)
{
	struct stream *ibuf;
    bfd_msg_hdr_t hdr = {0};
    bfd_msg_notify_t data = {0};
	bfpm_g->t_read = NULL;
    struct bfd_session *bs = NULL;
    struct sockaddr_any peer;
	size_t already;

	/*
	 * Check if async connect is now done.
	 */
	if (bfpm_g->state == BFPM_STATE_CONNECTING) {
		bfpm_connect_check();
		return 0;
	}

	assert(bfpm_g->state == BFPM_STATE_ESTABLISHED);
	assert(bfpm_g->sock >= 0);

	ibuf = bfpm_g->ibuf;
	already = stream_get_endp(ibuf);

	if (already < BFDSYNC_MSG_HDR_LEN) {
		ssize_t nbyte;

		nbyte = stream_read_try(ibuf, bfpm_g->sock,
					BFDSYNC_MSG_HDR_LEN - already);
		if (nbyte == 0 || nbyte == -1) {
			if (nbyte == -1) {
				char buffer[1024];

				snprintf(buffer, sizeof(buffer),
					 "closed socket in read(%d): %s", errno,
					 safe_strerror(errno));
				bfpm_connection_down(buffer);
			} else
				bfpm_connection_down("closed socket in read");
			return 0;
		}

		if (nbyte != (ssize_t)(BFDSYNC_MSG_HDR_LEN - already))
		{
			zlog_info("read bfd_msg hdr from bfdsyncd incomplete, nbyte:%ld actual:%ld", nbyte, (ssize_t)(BFDSYNC_MSG_HDR_LEN - already));
			goto done;
		}

		already = BFDSYNC_MSG_HDR_LEN;
	}

    // get bfd_msg hdr
	stream_set_getp(ibuf, 0);
	STREAM_GETC(ibuf, hdr.version);
	STREAM_GETC(ibuf, hdr.msg_type);
	STREAM_GETW(ibuf, hdr.msg_len);

	/*
	 * Read out the rest of the packet.
	 */
	if (already < hdr.msg_len) {
		ssize_t nbyte;

		nbyte = stream_read_try(ibuf, bfpm_g->sock, hdr.msg_len - already);

		if (nbyte == 0 || nbyte == -1) {
			if (nbyte == -1) {
				char buffer[1024];

				snprintf(buffer, sizeof(buffer),
					 "failed to read message(%d) %s", errno,
					 safe_strerror(errno));
				bfpm_connection_down(buffer);
			} else
				bfpm_connection_down("failed to read message");
			return 0;
		}

		if (nbyte != (ssize_t)(hdr.msg_len - already))
		{
			zlog_info("read bfd_msg notify from bfdsyncd incomplete, nbyte:%ld actual:%ld", nbyte, (ssize_t)(hdr.msg_len - already));
			goto done;
		}
	}

    data.recvCount = stream_getq(ibuf);
    data.sendCount = stream_getq(ibuf);
    STREAM_GETL(ibuf, data.remote_discr);
    STREAM_GET(data.bpc_peer, ibuf, INET6_ADDRSTRLEN);
    STREAM_GET(data.bfd_name, ibuf, MAXNAMELEN + 1);

    zlog_info("read from bfdsyncd, bfd_name:%s, ver:%u, notify status:%s, msglen:%u, peer:%s, remote_discr:%u, already:%zu",
        data.bfd_name, hdr.version, bfd_status_translate(hdr.msg_type), hdr.msg_len, data.bpc_peer, data.remote_discr, already);
    strtosa(data.bpc_peer, &peer);
    bs = bfd_find_disc(&peer, data.remote_discr);
    if (hdr.msg_type == BFD_NOTIFY_DOWN)
    {
        if (bs && (CHECK_FLAG(bs->hwbfd_flags, BFD_HWFLAG_SENDCREATE))) {
			UNSET_FLAG(bs->hwbfd_flags, BFD_HWFLAG_CREATE_SUCCESS);

			if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SBFD_ECHO))
			{
				bs->stats.rx_echo_pkt += data.recvCount;
				bs->stats.tx_echo_pkt += data.sendCount;
				bs->echo_hw_xmt_TO = 0;
				bs->echo_hw_detect_TO = 0;
				bfd_fpm_peer_sendmsg(bs, false);
				ptm_sbfd_sess_dn(bs, BD_ECHO_FAILED);
				ptm_bfd_start_xmt_timer(bs, true);
				bfd_echo_recvtimer_update(bs);
			}
			else
			{
				bs->stats.rx_ctrl_pkt += data.recvCount;
				bs->stats.tx_ctrl_pkt += data.sendCount;
				bfd_fpm_peer_sendmsg(bs, false);
				bfd_notify_down(bs);
				ptm_bfd_start_xmt_timer(bs, false);
				bfd_recvtimer_update(bs);
			}
			THREAD_OFF(bs->xmttimer_delay);

        }
    }
    else if (hdr.msg_type == BFD_NOTIFY_UP)
    {
        if (bs && (bs->xmttimer_ev || bs->echo_xmttimer_ev) && (CHECK_FLAG(bs->hwbfd_flags, BFD_HWFLAG_SENDCREATE)))
        {
			/*recv hw BFD_NOTIFY_UP msg, set flag BFD_HWFLAG_CREATE_SUCCESS*/
            SET_FLAG(bs->hwbfd_flags, BFD_HWFLAG_CREATE_SUCCESS);
			if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SBFD_ECHO))
			{
				/*
				 *  It is possible that the offload will be triggered again when the offload has already been sent.
				 *  If it is confirmed that the peer has been sent, the offload timer is deleted.
				*/
				sbfd_echo_hwoffloadtimer_delete(bs);

				/*
				 *  Confirm that the hardware has created a session. At this time, set the software pakcet to the configuration value.
				 *  Keep sending the bfd session pakcet before the hardware pakcet works normally.
				*/
				bs->echo_xmt_TO = bs->timers.desired_min_echo_tx;
				bs->echo_detect_TO = bs->detect_mult * bs->echo_xmt_TO;
				ptm_bfd_start_xmt_timer(bs, true);
			}

			if (!bs->xmttimer_delay)
			{
				thread_add_timer(master, bfd_xmtdel_delay_cb, bs, BFD_XMTDEL_DELAY_TIMER, &bs->xmttimer_delay);
			}
			else
			{
				THREAD_OFF(bs->xmttimer_delay);
				thread_add_timer(master, bfd_xmtdel_delay_cb, bs, BFD_XMTDEL_DELAY_TIMER, &bs->xmttimer_delay);
			}

        }
    }

	stream_set_getp(ibuf, 0);
	/*
	 * Read out the rest of the packet.
	 */

	bfpm_debug("Read out a full fpm message");

	/*
	 * Just throw it away for now.
	 */
	stream_reset(ibuf);

done:
	bfpm_read_on();
	return 0;

stream_failure:
	return -1;
}

/*
 * zfpm_writes_pending
 *
 * Returns true if we may have something to write to the FPM.
 */
static int bfpm_writes_pending(void)
{

	/*
	 * Check if there is any data in the outbound buffer that has not
	 * been written to the socket yet.
	 */
	if (stream_get_endp(bfpm_g->obuf) - stream_get_getp(bfpm_g->obuf))
		return 1;

	return 0;
}

/*
 * zfpm_write_cb
 */
static int bfpm_write_cb(struct thread *thread)
{
	struct stream *s;
	int num_writes;

	bfpm_g->t_write = NULL;

	/*
	 * Check if async connect is now done.
	 */
	if (bfpm_g->state == BFPM_STATE_CONNECTING) {
		bfpm_connect_check();
		return 0;
	}

	assert(bfpm_g->state == BFPM_STATE_ESTABLISHED);
	assert(bfpm_g->sock >= 0);

	num_writes = 0;

	do {
		int bytes_to_write, bytes_written;

		s = bfpm_g->obuf;

		bytes_to_write = stream_get_endp(s) - stream_get_getp(s);
		if (!bytes_to_write)
			break;

		bytes_written =
			write(bfpm_g->sock, stream_pnt(s), bytes_to_write);
		num_writes++;

		if (bytes_written < 0) {
			if (ERRNO_IO_RETRY(errno))
				break;

			bfpm_connection_down("failed to write to socket");
			return 0;
		}

		if (bytes_written != bytes_to_write) {

			/*
			 * Partial write.
			 */
			stream_forward_getp(s, bytes_written);
			break;
		}

		/*
		 * We've written out the entire contents of the stream.
		 */
		stream_reset(s);

		if (num_writes >= BFDSYNC_MAX_WRITES_PER_RUN) {
			break;
		}

		if (bfpm_thread_should_yield(thread)) {
			break;
		}
	} while (1);

	if (bfpm_writes_pending())
		bfpm_write_on();

	return 0;
}

/*
 * zfpm_connect_cb
 */
static int bfpm_connect_cb(struct thread *t)
{
	int sock, ret;
	struct sockaddr_in serv;

	bfpm_g->t_connect = NULL;
	assert(bfpm_g->state == BFPM_STATE_ACTIVE);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		bfpm_debug("Failed to create socket for connect(): %s",
			   strerror(errno));
		return 0;
	}

	set_nonblocking(sock);

	/* Make server socket. */
	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_port = htons(bfpm_g->fpm_port);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	serv.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */

	serv.sin_addr.s_addr = (bfpm_g->fpm_server);

	/*
	 * Connect to the FPM.
	 */
	bfpm_g->connect_calls++;
	bfpm_g->last_connect_call_time = monotime(NULL);

	ret = connect(sock, (struct sockaddr *)&serv, sizeof(serv));
	if (ret >= 0) {
		bfpm_g->sock = sock;
		bfpm_connection_up("connect succeeded");
		return 1;
	}

	if (errno == EINPROGRESS) {
		bfpm_g->sock = sock;
		bfpm_read_on();
		bfpm_write_on();
		bfpm_set_state(BFPM_STATE_CONNECTING,
			       "async connect in progress");
		return 0;
	}

	zlog_info("can't connect to FPM %d: %s", sock, safe_strerror(errno));
	close(sock);

	/*
	 * Restart timer for retrying connection.
	 */
	bfpm_start_connect_timer("connect() failed");
	return 0;
}

/*
 * zfpm_set_state
 *
 * Move state machine into the given state.
 */
static void bfpm_set_state(bfpm_state_t state, const char *reason)
{
	bfpm_state_t cur_state = bfpm_g->state;

	if (!reason)
		reason = "Unknown";

	if (state == cur_state)
		return;

	bfpm_debug("beginning state transition %s -> %s. Reason: %s",
		   bfpm_state_to_str(cur_state), bfpm_state_to_str(state),
		   reason);

	switch (state) {

	case BFPM_STATE_IDLE:
		assert(cur_state == BFPM_STATE_ESTABLISHED);
		break;

	case BFPM_STATE_ACTIVE:
		assert(cur_state == BFPM_STATE_IDLE
		       || cur_state == BFPM_STATE_CONNECTING);
		assert(bfpm_g->t_connect);
		break;

	case BFPM_STATE_CONNECTING:
		assert(bfpm_g->sock);
		assert(cur_state == BFPM_STATE_ACTIVE);
		assert(bfpm_g->t_read);
		assert(bfpm_g->t_write);
		break;

	case BFPM_STATE_ESTABLISHED:
		assert(cur_state == BFPM_STATE_ACTIVE
		       || cur_state == BFPM_STATE_CONNECTING);
		assert(bfpm_g->sock);
		assert(bfpm_g->t_read);
		assert(bfpm_g->t_write);
		break;
	}

	bfpm_g->state = state;
}

/*
 * zfpm_calc_connect_delay
 *
 * Returns the number of seconds after which we should attempt to
 * reconnect to the FPM.
 */
static long bfpm_calc_connect_delay(void)
{
	time_t elapsed;

	/*
	 * Return 0 if this is our first attempt to connect.
	 */
	if (bfpm_g->connect_calls == 0) {
		return 0;
	}

	elapsed = bfpm_get_elapsed_time(bfpm_g->last_connect_call_time);

	if (elapsed > BFPM_CONNECT_RETRY_IVL) {
		return 0;
	}

	return BFPM_CONNECT_RETRY_IVL - elapsed;
}

/*
 * zfpm_start_connect_timer
 */
static void bfpm_start_connect_timer(const char *reason)
{
	long delay_secs;

	assert(!bfpm_g->t_connect);
	assert(bfpm_g->sock < 0);

	assert(bfpm_g->state == BFPM_STATE_IDLE
	       || bfpm_g->state == BFPM_STATE_ACTIVE
	       || bfpm_g->state == BFPM_STATE_CONNECTING);

	delay_secs = bfpm_calc_connect_delay();
	bfpm_debug("scheduling connect in %ld seconds", delay_secs);

	thread_add_timer(bfpm_g->master, bfpm_connect_cb, 0, delay_secs,
			 &bfpm_g->t_connect);
	bfpm_set_state(BFPM_STATE_ACTIVE, reason);
}

/*
 * zfpm_is_enabled
 *
 * Returns true if the zebra FPM module has been enabled.
 */
static inline int bfpm_is_enabled(void)
{
	return bfpm_g->enabled;
}

/*
 * zfpm_conn_is_up
 *
 * Returns true if the connection to the FPM is up.
 */
static inline int bfpm_conn_is_up(void)
{
	if (bfpm_g->state != BFPM_STATE_ESTABLISHED)
		return 0;

	assert(bfpm_g->sock >= 0);

	return 1;
}
static int bfdsync_flush_data(struct thread *thread)
{
    bfpm_g->t_write = NULL;
    if (bfpm_g->sock < 0)
        return -1;
    switch (buffer_flush_available(bfpm_g->waitbuf, bfpm_g->sock)) {
    case BUFFER_ERROR:
        flog_err(
            EC_LIB_ZAPI_SOCKET,
            "%s: buffer_flush_available failed on zclient fd %d, closing",
            __func__, bfpm_g->sock);
        bfpm_connect_check();
        return -1;
    case BUFFER_PENDING:
        bfpm_g->t_write = NULL;
        thread_add_write(bfpm_g->master, bfdsync_flush_data, 0,
                 bfpm_g->sock, &bfpm_g->t_write);
        break;
    case BUFFER_EMPTY:
        break;
    }
    return 0;
}

static int bfdsync_send_message(void)
{
    if (bfpm_g->sock < 0)
        return -1;
    switch (buffer_write(bfpm_g->waitbuf, bfpm_g->sock, STREAM_DATA(bfpm_g->obuf),
               stream_get_endp(bfpm_g->obuf)))
    {
        case BUFFER_ERROR:
            zlog_warn("%s: buffer_write failed to zclient fd %d, closing",
                __func__, bfpm_g->sock);
            bfpm_connect_check();
            return -1;
        case BUFFER_EMPTY:
            THREAD_OFF(bfpm_g->t_write);
            break;
        case BUFFER_PENDING:
            bfpm_g->t_write = NULL;
		thread_add_write(bfpm_g->master, bfdsync_flush_data, 0,
				 bfpm_g->sock, &bfpm_g->t_write);
            break;
    }
  return 0;

}

void extract_segment_from_addr_list(char * segment, size_t max_size, struct in6_addr seg_list[], int seg_num)
{
	char tmp[64];
	int i = 0;

	if(NULL == segment){
		return;
	}

	memset(segment, 0, max_size);

	do
	{
		if(strlen(segment) >= max_size){
			break;
		}

		if(i >= seg_num){
			break;
		}

		if(i > 0){
		    strcat(segment, ",");
		}

		memset(tmp, 0, 64);
		inet_ntop(AF_INET6, &seg_list[i], tmp, 64);
		strcat(segment, tmp);
		i++;

	}while(true);

	return;
}
/*
 * bfd_peer_sendmsg - Format and send a peer register/Unregister
 *                    command to Zebra to be forwarded to BFD
 */
void bfd_fpm_peer_sendmsg(struct bfd_session *bfd, bool create)
{
	struct stream *msg = NULL;
	int ret;
	bfd_msg_hdr_t *hdr = NULL;
	bfd_msg_data_t *data = NULL;
	unsigned char *buf;
	int msg_len = 0;

	if (!bfd->allow_offload)
		return;

	/* Individual reg/dereg messages are suppressed during shutdown.
	if (CHECK_FLAG(bfd_gbl.flags, BFD_GBL_FLAG_IN_SHUTDOWN)) {
		if (bfd_debug)
			zlog_debug(
				"%s: Suppressing BFD peer reg/dereg messages",
				__FUNCTION__);
		return;
	}*/

	/* Check socket. */
	if (!bfpm_g || bfpm_g->sock < 0) {
		zlog_debug(
			"%s: Can't send BFD peer register, BfdFpm client not "
			"established",
			__FUNCTION__);
		return;
	}
	msg = bfpm_g->obuf;
	stream_reset(msg);
	buf = STREAM_DATA(msg);
	hdr = (bfd_msg_hdr_t *)buf;
	hdr->version = BFDSYNC_PROTO_VERSION;
	if (create)
	{
		hdr->msg_type = BFD_CREATE_SESSION;
		SET_FLAG(bfd->hwbfd_flags, BFD_HWFLAG_SENDCREATE);
	}
	else
	{
		hdr->msg_type = BFD_DELETE_SESSION;
		UNSET_FLAG(bfd->hwbfd_flags, BFD_HWFLAG_SENDCREATE);
		UNSET_FLAG(bfd->hwbfd_flags, BFD_HWFLAG_CREATE_SUCCESS);
		UNSET_FLAG(bfd->hwbfd_flags, BFD_HWFLAG_DELAYSENDCREATE);
		bfd->counterOid = 0;
	}

	data = (bfd_msg_data_t *)bfdsync_msg_data(hdr);
	data->bpc_mhop = (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_MH)) ? 1:0;
	if (bfd->key.family == AF_INET)
		data->bpc_ipv4 = 1;
	else
		data->bpc_ipv4 = 0;
	data->bpc_detectmultiplier = bfd->remote_detect_mult;
	data->bpc_localmultiplier = bfd->detect_mult;
	data->bpc_txinterval = htonl((uint32_t)bfd->xmt_TO);
	data->bpc_recvinterval = htonl((uint32_t)bfd->detect_TO / bfd->remote_detect_mult);
	data->desired_tx_interval = htonl((uint32_t)bfd->timers.desired_min_tx);
	data->desired_rx_interval = htonl((uint32_t)bfd->timers.required_min_rx);
	inet_ntop(bfd->key.family, &bfd->key.local, data->bpc_local,
		  sizeof(data->bpc_local));
	inet_ntop(bfd->key.family, &bfd->key.peer, data->bpc_peer,
		  sizeof(data->bpc_peer));

	data->src_port = htons((uint16_t)bfd->srcport);
	data->dest_port = (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_MH))
					 ? htons(BFD_DEF_MHOP_DEST_PORT)
					 : htons(BFD_DEFDESTPORT);
	data->discrs.my_discr = htonl(bfd->discrs.my_discr);
	data->discrs.remote_discr = htonl(bfd->discrs.remote_discr);
	data->ttl = (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_MH))
					 ? bfd->mh_ttl
					 : 255;
	strncpy(data->bpc_vrfname, bfd->key.vrfname, MAXNAMELEN);
	strncpy(data->bpc_localif, bfd->key.ifname, MAXNAMELEN);

	data->bpc_type = BPC_TYPE_CLASSIC_BFD;

	if (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_SBFD_ECHO))
	{
		data->src_port = htons(BFD_DEFDESTPORT);
		data->dest_port = htons(BFD_DEF_ECHO_PORT);
		data->bpc_type = BPC_TYPE_SBFD_ECHO;
		data->bpc_txinterval = htonl((uint32_t)bfd->echo_hw_xmt_TO);
		data->bpc_recvinterval = htonl((uint32_t)bfd->echo_hw_detect_TO / bfd->detect_mult);
		data->discrs.remote_discr = htonl(bfd->discrs.my_discr);

		extract_segment_from_addr_list(data->bpc_segment, MAXNAMELEN, bfd->seg_list, bfd->segnum);
		zlog_debug("bfd_peer_sendmsg: segment: %s, sport:%d, dport:%d", data->bpc_segment, htons(data->src_port), htons(data->dest_port));

	}

	if (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_SBFD_INIT))
	{
		data->src_port = htons(BFD_DEFDESTPORT);
		data->dest_port = htons(BFD_DEF_SBFD_DEST_PORT);
		data->bpc_type = BPC_TYPE_SBFD_INIT;

		extract_segment_from_addr_list(data->bpc_segment, MAXNAMELEN, bfd->seg_list, bfd->segnum);
		zlog_debug("bfd_peer_sendmsg: segment: %s, sport:%d, dport:%d", data->bpc_segment, htons(data->src_port), htons(data->dest_port));
	}

	strlcpy(data->bfd_name, bfd->bfd_name, MAXNAMELEN);

	msg_len = sizeof(bfd_msg_data_t) + sizeof(bfd_msg_hdr_t);
	hdr->msg_len = htons(msg_len);
	stream_forward_endp(msg, msg_len);
	ret = bfdsync_send_message();

	if (ret < 0) {
		zlog_debug(
			"bfd_peer_sendmsg: zclient_send_message() failed");
	}

	return;
}

/*
 * bfd_fpm_sbfd_reflector_sendmsg - Format and send a sbfd reflector register/Unregister
 */
void bfd_fpm_sbfd_reflector_sendmsg(struct sbfd_reflector *sr, bool create)
{
    struct stream *msg = NULL;
    int ret;
    bfd_msg_hdr_t *hdr = NULL;
    bfd_msg_data_t *data = NULL;
    unsigned char *buf;
    int msg_len = 0;

    if (!is_hw_bfd_enabled())
        return;

    /* Check socket. */
    if (!bfpm_g || bfpm_g->sock < 0) {
        zlog_debug(
            "%s: Can't send BFD peer register, BfdFpm client not "
            "established",
            __FUNCTION__);
        return;
    }
    msg = bfpm_g->obuf;
    stream_reset(msg);
    buf = STREAM_DATA(msg);
    hdr = (bfd_msg_hdr_t *)buf;
    hdr->version = BFDSYNC_PROTO_VERSION;
	hdr->msg_type = create ? BFD_CREATE_SESSION : BFD_DELETE_SESSION;

    data = (bfd_msg_data_t *)bfdsync_msg_data(hdr);
    data->discrs.my_discr = htonl(sr->discr);
	inet_ntop(sr->family, &sr->local, data->bpc_local, sizeof(data->bpc_local));
	strncpy(data->bpc_vrfname, VRF_DEFAULT_NAME, MAXNAMELEN);
	data->bpc_type = BPC_TYPE_SBFD_RFLT;

	if (sr->family == AF_INET)
        data->bpc_ipv4 = 1;
    else
        data->bpc_ipv4 = 0;

    msg_len = sizeof(bfd_msg_data_t) + sizeof(bfd_msg_hdr_t);
    hdr->msg_len = htons(msg_len);
    stream_forward_endp(msg, msg_len);
    ret = bfdsync_send_message();

    if (ret < 0) {
        zlog_debug(
            "bfd_fpm_sbfd_reflector_sendmsg: zclient_send_message() failed");
    }

    return;
}
/**
 * zfpm_init
 *
 * One-time initialization of the Zebra FPM module.
 *
 * @param[in] port port at which FPM is running.
 * @param[in] enable true if the zebra FPM module should be enabled
 * @param[in] format to use to talk to the FPM. Can be 'netink' or 'protobuf'.
 *
 * Returns true on success.
 */
int bfpm_init(struct thread_master *master)
{
	memset(bfpm_g, 0, sizeof(*bfpm_g));
	bfpm_g->master = master;

	bfpm_g->sock = -1;
	bfpm_g->state = BFPM_STATE_IDLE;

	/*
	 * Disable FPM interface if no suitable format is available.
	 */

	bfpm_g->enabled = 1;

	bfpm_g->fpm_server = BFDSYNCD_DEFAULT_IP;

	bfpm_g->fpm_port = 2720;

	bfpm_g->obuf = stream_new(BFPM_OBUF_SIZE);
	bfpm_g->ibuf = stream_new(BFPM_IBUF_SIZE);
    bfpm_g->waitbuf = buffer_new(0);

	bfpm_start_connect_timer("initialized");
	return 0;
}

static void _bfd_send_bfpm_srmsg(struct hash_bucket *hb, void *arg)
{
	struct sbfd_reflector *sr = hb->data;
	bfd_fpm_sbfd_reflector_sendmsg(sr, true);
}
