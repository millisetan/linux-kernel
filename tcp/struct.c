struct tcp_sock {
	/* inet_connection_sock has to be the first member of tcp_sock */
	struct inet_connection_sock	inet_conn;
	u16	tcp_header_len;	/* Bytes of tcp header to send		*/
	u16	gso_segs;	/* Max number of segs per GSO packet	*/

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */
	__be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */
	u64	bytes_received;	/* RFC4898 tcpEStatsAppHCThruOctetsReceived
				 * sum(delta(rcv_nxt)), or how many bytes
				 * were acked.
				 */
	u32	segs_in;	/* RFC4898 tcpEStatsPerfSegsIn
				 * total number of segments in.
				 */
	u32	data_segs_in;	/* RFC4898 tcpEStatsPerfDataSegsIn
				 * total number of data segments in.
				 */
 	u32	rcv_nxt;	/* What we want to receive next 	*/
	u32	copied_seq;	/* Head of yet unread data		*/
	u32	rcv_wup;	/* rcv_nxt on last window update sent	*/
 	u32	snd_nxt;	/* Next sequence we send		*/
	u32	segs_out;	/* RFC4898 tcpEStatsPerfSegsOut
				 * The total number of segments sent.
				 */
	u32	data_segs_out;	/* RFC4898 tcpEStatsPerfDataSegsOut
				 * total number of data segments sent.
				 */
	u64	bytes_sent;	/* RFC4898 tcpEStatsPerfHCDataOctetsOut
				 * total number of data bytes sent.
				 */
	u64	bytes_acked;	/* RFC4898 tcpEStatsAppHCThruOctetsAcked
				 * sum(delta(snd_una)), or how many bytes
				 * were acked.
				 */
	u32	dsack_dups;	/* RFC4898 tcpEStatsStackDSACKDups
				 * total number of DSACK blocks received
				 */
 	u32	snd_una;	/* First byte we want an ack for	*/
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */
	u32	last_oow_ack_time;  /* timestamp of last out-of-window ACK */
	u32	compressed_ack_rcv_nxt;

	u32	tsoffset;	/* timestamp offset */

	struct list_head tsq_node; /* anchor in tsq_tasklet.head list */
	struct list_head tsorted_sent_queue; /* time-sorted sent but un-SACKed skbs */

	u32	snd_wl1;	/* Sequence for window update		*/
	u32	snd_wnd;	/* The window we expect to receive	*/
	u32	max_window;	/* Maximal window ever seen from peer	*/
	u32	mss_cache;	/* Cached effective mss, not including SACKS */

	u32	window_clamp;	/* Maximal window to advertise		*/
	u32	rcv_ssthresh;	/* Current window clamp			*/

	/* Information of the most recently (s)acked skb */
	struct tcp_rack {
		u64 mstamp; /* (Re)sent time of the skb */
		u32 rtt_us;  /* Associated RTT */
		u32 end_seq; /* Ending TCP sequence of the skb */
		u32 last_delivered; /* tp->delivered at last reo_wnd adj */
		u8 reo_wnd_steps;   /* Allowed reordering window */
#define TCP_RACK_RECOVERY_THRESH 16
		u8 reo_wnd_persist:5, /* No. of recovery since last adj */
		   dsack_seen:1, /* Whether DSACK seen after last adj */
		   advanced:1;	 /* mstamp advanced since last lost marking */
	} rack;
	u16	advmss;		/* Advertised MSS			*/
	u8	compressed_ack;
	u32	chrono_start;	/* Start time in jiffies of a TCP chrono */
	u32	chrono_stat[3];	/* Time in jiffies for chrono_stat stats */
	u8	chrono_type:2,	/* current chronograph type */
		rate_app_limited:1,  /* rate_{delivered,interval_us} limited? */
		fastopen_connect:1, /* FASTOPEN_CONNECT sockopt */
		fastopen_no_cookie:1, /* Allow send/recv SYN+data without a cookie */
		is_sack_reneg:1,    /* in recovery from loss with SACK reneg? */
		unused:2;
	u8	nonagle     : 4,/* Disable Nagle algorithm?             */
		thin_lto    : 1,/* Use linear timeouts for thin streams */
		recvmsg_inq : 1,/* Indicate # of bytes in queue upon recvmsg */
		repair      : 1,
		frto        : 1;/* F-RTO (RFC5682) activated in CA_Loss */
	u8	repair_queue;
	u8	syn_data:1,	/* SYN includes data */
		syn_fastopen:1,	/* SYN includes Fast Open option */
		syn_fastopen_exp:1,/* SYN includes Fast Open exp. option */
		syn_fastopen_ch:1, /* Active TFO re-enabling probe */
		syn_data_acked:1,/* data in SYN is acked by SYN-ACK */
		save_syn:1,	/* Save headers of SYN packet */
		is_cwnd_limited:1,/* forward progress limited by snd_cwnd? */
		syn_smc:1;	/* SYN includes SMC */
	u32	tlp_high_seq;	/* snd_nxt at the time of TLP retransmit. */

/* RTT measurement */
	u64	tcp_mstamp;	/* most recent packet received/sent */
	u32	srtt_us;	/* smoothed round trip time << 3 in usecs */
	u32	mdev_us;	/* medium deviation			*/
	u32	mdev_max_us;	/* maximal mdev for the last rtt period	*/
	u32	rttvar_us;	/* smoothed mdev_max			*/
	u32	rtt_seq;	/* sequence number to update rttvar	*/
	struct  minmax rtt_min;

	u32	packets_out;	/* Packets which are "in flight"	*/
	u32	retrans_out;	/* Retransmitted packets out		*/
	u32	max_packets_out;  /* max packets_out in last window */
	u32	max_packets_seq;  /* right edge of max_packets_out flight */

	u16	urg_data;	/* Saved octet of OOB data and control flags */
	u8	ecn_flags;	/* ECN status bits.			*/
	u8	keepalive_probes; /* num of allowed keep alive probes	*/
	u32	reordering;	/* Packet reordering metric.		*/
	u32	reord_seen;	/* number of data packet reordering events */
	u32	snd_up;		/* Urgent pointer		*/

/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
	struct tcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
 	u32	snd_ssthresh;	/* Slow start size threshold		*/
 	u32	snd_cwnd;	/* Sending congestion window		*/
	u32	snd_cwnd_cnt;	/* Linear increase counter		*/
	u32	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */
	u32	snd_cwnd_used;
	u32	snd_cwnd_stamp;
	u32	prior_cwnd;	/* cwnd right before starting loss recovery */
	u32	prr_delivered;	/* Number of newly delivered packets to
				 * receiver in Recovery. */
	u32	prr_out;	/* Total number of pkts sent during Recovery. */
	u32	delivered;	/* Total data packets delivered incl. rexmits */
	u32	delivered_ce;	/* Like the above but only ECE marked packets */
	u32	lost;		/* Total data packets lost incl. rexmits */
	u32	app_limited;	/* limited until "delivered" reaches this val */
	u64	first_tx_mstamp;  /* start of window send phase */
	u64	delivered_mstamp; /* time we reached "delivered" */
	u32	rate_delivered;    /* saved rate sample: packets delivered */
	u32	rate_interval_us;  /* saved rate sample: time elapsed */

 	u32	rcv_wnd;	/* Current receiver window		*/
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
	u32	notsent_lowat;	/* TCP_NOTSENT_LOWAT */
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
	u32	lost_out;	/* Lost packets			*/
	u32	sacked_out;	/* SACK'd packets			*/

	struct hrtimer	pacing_timer;
	struct hrtimer	compressed_ack_timer;

	/* from STCP, retrans queue hinting */
	struct sk_buff* lost_skb_hint;
	struct sk_buff *retransmit_skb_hint;

	/* OOO segments go in this rbtree. Socket lock must be held. */
	struct rb_root	out_of_order_queue;
	struct sk_buff	*ooo_last_skb; /* cache rb_last(out_of_order_queue) */

	/* SACKs data, these 2 need to be together (see tcp_options_write) */
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	struct tcp_sack_block recv_sack_cache[4];

	struct sk_buff *highest_sack;   /* skb just after the highest
					 * skb with SACKed bit set
					 * (validity guaranteed only if
					 * sacked_out > 0)
					 */

	int     lost_cnt_hint;

	u32	prior_ssthresh; /* ssthresh saved at recovery start	*/
	u32	high_seq;	/* snd_nxt at onset of congestion	*/

	u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
	u32	undo_marker;	/* snd_una upon a new recovery episode. */
	int	undo_retrans;	/* number of undoable retransmissions. */
	u64	bytes_retrans;	/* RFC4898 tcpEStatsPerfOctetsRetrans
				 * Total data bytes retransmitted
				 */
	u32	total_retrans;	/* Total retransmits for entire connection */

	u32	urg_seq;	/* Seq of received urgent pointer */
	unsigned int		keepalive_time;	  /* time before keep alive takes place */
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */

	int			linger2;


/* Sock_ops bpf program related variables */
#ifdef CONFIG_BPF
	u8	bpf_sock_ops_cb_flags;  /* Control calling BPF programs
					 * values defined in uapi/linux/tcp.h
					 */
#define BPF_SOCK_OPS_TEST_FLAG(TP, ARG) (TP->bpf_sock_ops_cb_flags & ARG)
#else
#define BPF_SOCK_OPS_TEST_FLAG(TP, ARG) 0
#endif

/* Receiver side RTT estimation */
	u32 rcv_rtt_last_tsecr;
	struct {
		u32	rtt_us;
		u32	seq;
		u64	time;
	} rcv_rtt_est;

/* Receiver queue space */
	struct {
		u32	space;
		u32	seq;
		u64	time;
	} rcvq_space;

/* TCP-specific MTU probe information. */
	struct {
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;
	u32	mtu_info; /* We received an ICMP_FRAG_NEEDED / ICMPV6_PKT_TOOBIG
			   * while socket was owned by user.
			   */

#ifdef CONFIG_TCP_MD5SIG
/* TCP AF-Specific parts; only used by MD5 Signature support so far */
	const struct tcp_sock_af_ops	*af_specific;

/* TCP MD5 Signature Option information */
	struct tcp_md5sig_info	__rcu *md5sig_info;
#endif

/* TCP fastopen related information */
	struct tcp_fastopen_request *fastopen_req;
	/* fastopen_rsk points to request_sock that resulted in this big
	 * socket. Used to retransmit SYNACKs etc.
	 */
	struct request_sock *fastopen_rsk;
	u32	*saved_syn;
};

/** inet_connection_sock - INET connection oriented sock
 *
 * @icsk_accept_queue:	   FIFO of established children
 * @icsk_bind_hash:	   Bind node
 * @icsk_timeout:	   Timeout
 * @icsk_retransmit_timer: Resend (no ack)
 * @icsk_rto:		   Retransmit timeout
 * @icsk_pmtu_cookie	   Last pmtu seen by socket
 * @icsk_ca_ops		   Pluggable congestion control hook
 * @icsk_af_ops		   Operations which are AF_INET{4,6} specific
 * @icsk_ulp_ops	   Pluggable ULP control hook
 * @icsk_ulp_data	   ULP private data
 * @icsk_clean_acked	   Clean acked data hook
 * @icsk_listen_portaddr_node	hash to the portaddr listener hashtable
 * @icsk_ca_state:	   Congestion control state
 * @icsk_retransmits:	   Number of unrecovered [RTO] timeouts
 * @icsk_pending:	   Scheduled timer event
 * @icsk_backoff:	   Backoff
 * @icsk_syn_retries:      Number of allowed SYN (or equivalent) retries
 * @icsk_probes_out:	   unanswered 0 window probes
 * @icsk_ext_hdr_len:	   Network protocol overhead (IP/IPv6 options)
 * @icsk_ack:		   Delayed ACK control data
 * @icsk_mtup;		   MTU probing control data
 */
struct inet_connection_sock {
	/* inet_sock has to be the first member! */
	struct inet_sock	  icsk_inet;
	struct request_sock_queue icsk_accept_queue;
	struct inet_bind_bucket	  *icsk_bind_hash;
	unsigned long		  icsk_timeout;
 	struct timer_list	  icsk_retransmit_timer;
 	struct timer_list	  icsk_delack_timer;
	__u32			  icsk_rto;
	__u32			  icsk_pmtu_cookie;
	const struct tcp_congestion_ops *icsk_ca_ops;
	const struct inet_connection_sock_af_ops *icsk_af_ops;
	const struct tcp_ulp_ops  *icsk_ulp_ops;
	void			  *icsk_ulp_data;
	void (*icsk_clean_acked)(struct sock *sk, u32 acked_seq);
	struct hlist_node         icsk_listen_portaddr_node;
	unsigned int		  (*icsk_sync_mss)(struct sock *sk, u32 pmtu);
	__u8			  icsk_ca_state:6,
				  icsk_ca_setsockopt:1,
				  icsk_ca_dst_locked:1;
	__u8			  icsk_retransmits;
	__u8			  icsk_pending;
	__u8			  icsk_backoff;
	__u8			  icsk_syn_retries;
	__u8			  icsk_probes_out;
	__u16			  icsk_ext_hdr_len;
	struct {
		__u8		  pending;	 /* ACK is pending			   */
		__u8		  quick;	 /* Scheduled number of quick acks	   */
		__u8		  pingpong;	 /* The session is interactive		   */
		__u8		  blocked;	 /* Delayed ACK was blocked by socket lock */
		__u32		  ato;		 /* Predicted tick of soft clock	   */
		unsigned long	  timeout;	 /* Currently scheduled timeout		   */
		__u32		  lrcvtime;	 /* timestamp of last received data packet */
		__u16		  last_seg_size; /* Size of last incoming segment	   */
		__u16		  rcv_mss;	 /* MSS used for delayed ACK decisions	   */
	} icsk_ack;
	struct {
		int		  enabled;

		/* Range of MTUs to search */
		int		  search_high;
		int		  search_low;

		/* Information on the current probe. */
		int		  probe_size;

		u32		  probe_timestamp;
	} icsk_mtup;
	u32			  icsk_user_timeout;

	u64			  icsk_ca_priv[88 / sizeof(u64)];
#define ICSK_CA_PRIV_SIZE      (11 * sizeof(u64))
};

/** struct inet_sock - representation of INET sockets
 *
 * @sk - ancestor class
 * @pinet6 - pointer to IPv6 control block
 * @inet_daddr - Foreign IPv4 addr
 * @inet_rcv_saddr - Bound local IPv4 addr
 * @inet_dport - Destination port
 * @inet_num - Local port
 * @inet_saddr - Sending source
 * @uc_ttl - Unicast TTL
 * @inet_sport - Source port
 * @inet_id - ID counter for DF pkts
 * @tos - TOS
 * @mc_ttl - Multicasting TTL
 * @is_icsk - is this an inet_connection_sock?
 * @uc_index - Unicast outgoing device index
 * @mc_index - Multicast device index
 * @mc_list - Group array
 * @cork - info to build ip hdr on each ip frag while socket is corked
 */
struct inet_sock {
	/* sk and pinet6 has to be the first two members of inet_sock */
	struct sock		sk;
#if IS_ENABLED(CONFIG_IPV6)
	struct ipv6_pinfo	*pinet6;
#endif
	/* Socket demultiplex comparisons on incoming packets. */
#define inet_daddr		sk.__sk_common.skc_daddr
#define inet_rcv_saddr		sk.__sk_common.skc_rcv_saddr
#define inet_dport		sk.__sk_common.skc_dport
#define inet_num		sk.__sk_common.skc_num

	__be32			inet_saddr;
	__s16			uc_ttl;
	__u16			cmsg_flags;
	__be16			inet_sport;
	__u16			inet_id;

	struct ip_options_rcu __rcu	*inet_opt;
	int			rx_dst_ifindex;
	__u8			tos;
	__u8			min_ttl;
	__u8			mc_ttl;
	__u8			pmtudisc;
	__u8			recverr:1,
				is_icsk:1,
				freebind:1,
				hdrincl:1,
				mc_loop:1,
				transparent:1,
				mc_all:1,
				nodefrag:1;
	__u8			bind_address_no_port:1,
				defer_connect:1; /* Indicates that fastopen_connect is set
						  * and cookie exists so we defer connect
						  * until first data frame is written
						  */
	__u8			rcv_tos;
	__u8			convert_csum;
	int			uc_index;
	int			mc_index;
	__be32			mc_addr;
	struct ip_mc_socklist __rcu	*mc_list;
	struct inet_cork_full	cork;
};

/**
  *	struct sock - network layer representation of sockets
  *	@__sk_common: shared layout with inet_timewait_sock
  *	@sk_shutdown: mask of %SEND_SHUTDOWN and/or %RCV_SHUTDOWN
  *	@sk_userlocks: %SO_SNDBUF and %SO_RCVBUF settings
  *	@sk_lock:	synchronizer
  *	@sk_kern_sock: True if sock is using kernel lock classes
  *	@sk_rcvbuf: size of receive buffer in bytes
  *	@sk_wq: sock wait queue and async head
  *	@sk_rx_dst: receive input route used by early demux
  *	@sk_dst_cache: destination cache
  *	@sk_dst_pending_confirm: need to confirm neighbour
  *	@sk_policy: flow policy
  *	@sk_receive_queue: incoming packets
  *	@sk_wmem_alloc: transmit queue bytes committed
  *	@sk_tsq_flags: TCP Small Queues flags
  *	@sk_write_queue: Packet sending queue
  *	@sk_omem_alloc: "o" is "option" or "other"
  *	@sk_wmem_queued: persistent queue size
  *	@sk_forward_alloc: space allocated forward
  *	@sk_napi_id: id of the last napi context to receive data for sk
  *	@sk_ll_usec: usecs to busypoll when there is no data
  *	@sk_allocation: allocation mode
  *	@sk_pacing_rate: Pacing rate (if supported by transport/packet scheduler)
  *	@sk_pacing_status: Pacing status (requested, handled by sch_fq)
  *	@sk_max_pacing_rate: Maximum pacing rate (%SO_MAX_PACING_RATE)
  *	@sk_sndbuf: size of send buffer in bytes
  *	@__sk_flags_offset: empty field used to determine location of bitfield
  *	@sk_padding: unused element for alignment
  *	@sk_no_check_tx: %SO_NO_CHECK setting, set checksum in TX packets
  *	@sk_no_check_rx: allow zero checksum in RX packets
  *	@sk_route_caps: route capabilities (e.g. %NETIF_F_TSO)
  *	@sk_route_nocaps: forbidden route capabilities (e.g NETIF_F_GSO_MASK)
  *	@sk_gso_type: GSO type (e.g. %SKB_GSO_TCPV4)
  *	@sk_gso_max_size: Maximum GSO segment size to build
  *	@sk_gso_max_segs: Maximum number of GSO segments
  *	@sk_pacing_shift: scaling factor for TCP Small Queues
  *	@sk_lingertime: %SO_LINGER l_linger setting
  *	@sk_backlog: always used with the per-socket spinlock held
  *	@sk_callback_lock: used with the callbacks in the end of this struct
  *	@sk_error_queue: rarely used
  *	@sk_prot_creator: sk_prot of original sock creator (see ipv6_setsockopt,
  *			  IPV6_ADDRFORM for instance)
  *	@sk_err: last error
  *	@sk_err_soft: errors that don't cause failure but are the cause of a
  *		      persistent failure not just 'timed out'
  *	@sk_drops: raw/udp drops counter
  *	@sk_ack_backlog: current listen backlog
  *	@sk_max_ack_backlog: listen backlog set in listen()
  *	@sk_uid: user id of owner
  *	@sk_priority: %SO_PRIORITY setting
  *	@sk_type: socket type (%SOCK_STREAM, etc)
  *	@sk_protocol: which protocol this socket belongs in this network family
  *	@sk_peer_pid: &struct pid for this socket's peer
  *	@sk_peer_cred: %SO_PEERCRED setting
  *	@sk_rcvlowat: %SO_RCVLOWAT setting
  *	@sk_rcvtimeo: %SO_RCVTIMEO setting
  *	@sk_sndtimeo: %SO_SNDTIMEO setting
  *	@sk_txhash: computed flow hash for use on transmit
  *	@sk_filter: socket filtering instructions
  *	@sk_timer: sock cleanup timer
  *	@sk_stamp: time stamp of last packet received
  *	@sk_stamp_seq: lock for accessing sk_stamp on 32 bit architectures only
  *	@sk_tsflags: SO_TIMESTAMPING socket options
  *	@sk_tskey: counter to disambiguate concurrent tstamp requests
  *	@sk_zckey: counter to order MSG_ZEROCOPY notifications
  *	@sk_socket: Identd and reporting IO signals
  *	@sk_user_data: RPC layer private data
  *	@sk_frag: cached page frag
  *	@sk_peek_off: current peek_offset value
  *	@sk_send_head: front of stuff to transmit
  *	@sk_security: used by security modules
  *	@sk_mark: generic packet mark
  *	@sk_cgrp_data: cgroup data for this cgroup
  *	@sk_memcg: this socket's memory cgroup association
  *	@sk_write_pending: a write to stream socket waits to start
  *	@sk_state_change: callback to indicate change in the state of the sock
  *	@sk_data_ready: callback to indicate there is data to be processed
  *	@sk_write_space: callback to indicate there is bf sending space available
  *	@sk_error_report: callback to indicate errors (e.g. %MSG_ERRQUEUE)
  *	@sk_backlog_rcv: callback to process the backlog
  *	@sk_destruct: called at sock freeing time, i.e. when all refcnt == 0
  *	@sk_reuseport_cb: reuseport group container
  *	@sk_rcu: used during RCU grace period
  *	@sk_clockid: clockid used by time-based scheduling (SO_TXTIME)
  *	@sk_txtime_deadline_mode: set deadline mode for SO_TXTIME
  *	@sk_txtime_unused: unused txtime flags
  */
struct sock {
	/*
	 * Now struct inet_timewait_sock also uses sock_common, so please just
	 * don't add nothing before this first member (__sk_common) --acme
	 */
	struct sock_common	__sk_common;
#define sk_node			__sk_common.skc_node
#define sk_nulls_node		__sk_common.skc_nulls_node
#define sk_refcnt		__sk_common.skc_refcnt
#define sk_tx_queue_mapping	__sk_common.skc_tx_queue_mapping
#ifdef CONFIG_XPS
#define sk_rx_queue_mapping	__sk_common.skc_rx_queue_mapping
#endif

#define sk_dontcopy_begin	__sk_common.skc_dontcopy_begin
#define sk_dontcopy_end		__sk_common.skc_dontcopy_end
#define sk_hash			__sk_common.skc_hash
#define sk_portpair		__sk_common.skc_portpair
#define sk_num			__sk_common.skc_num
#define sk_dport		__sk_common.skc_dport
#define sk_addrpair		__sk_common.skc_addrpair
#define sk_daddr		__sk_common.skc_daddr
#define sk_rcv_saddr		__sk_common.skc_rcv_saddr
#define sk_family		__sk_common.skc_family
#define sk_state		__sk_common.skc_state
#define sk_reuse		__sk_common.skc_reuse
#define sk_reuseport		__sk_common.skc_reuseport
#define sk_ipv6only		__sk_common.skc_ipv6only
#define sk_net_refcnt		__sk_common.skc_net_refcnt
#define sk_bound_dev_if		__sk_common.skc_bound_dev_if
#define sk_bind_node		__sk_common.skc_bind_node
#define sk_prot			__sk_common.skc_prot
#define sk_net			__sk_common.skc_net
#define sk_v6_daddr		__sk_common.skc_v6_daddr
#define sk_v6_rcv_saddr	__sk_common.skc_v6_rcv_saddr
#define sk_cookie		__sk_common.skc_cookie
#define sk_incoming_cpu		__sk_common.skc_incoming_cpu
#define sk_flags		__sk_common.skc_flags
#define sk_rxhash		__sk_common.skc_rxhash

	socket_lock_t		sk_lock;
	atomic_t		sk_drops;
	int			sk_rcvlowat;
	struct sk_buff_head	sk_error_queue;
	struct sk_buff_head	sk_receive_queue;
	/*
	 * The backlog queue is special, it is always used with
	 * the per-socket spinlock held and requires low latency
	 * access. Therefore we special case it's implementation.
	 * Note : rmem_alloc is in this structure to fill a hole
	 * on 64bit arches, not because its logically part of
	 * backlog.
	 */
	struct {
		atomic_t	rmem_alloc;
		int		len;
		struct sk_buff	*head;
		struct sk_buff	*tail;
	} sk_backlog;
#define sk_rmem_alloc sk_backlog.rmem_alloc

	int			sk_forward_alloc;
#ifdef CONFIG_NET_RX_BUSY_POLL
	unsigned int		sk_ll_usec;
	/* ===== mostly read cache line ===== */
	unsigned int		sk_napi_id;
#endif
	int			sk_rcvbuf;

	struct sk_filter __rcu	*sk_filter;
	union {
		struct socket_wq __rcu	*sk_wq;
		struct socket_wq	*sk_wq_raw;
	};
#ifdef CONFIG_XFRM
	struct xfrm_policy __rcu *sk_policy[2];
#endif
	struct dst_entry	*sk_rx_dst;
	struct dst_entry __rcu	*sk_dst_cache;
	atomic_t		sk_omem_alloc;
	int			sk_sndbuf;

	/* ===== cache line for TX ===== */
	int			sk_wmem_queued;
	refcount_t		sk_wmem_alloc;
	unsigned long		sk_tsq_flags;
	union {
		struct sk_buff	*sk_send_head;
		struct rb_root	tcp_rtx_queue;
	};
	struct sk_buff_head	sk_write_queue;
	__s32			sk_peek_off;
	int			sk_write_pending;
	__u32			sk_dst_pending_confirm;
	u32			sk_pacing_status; /* see enum sk_pacing */
	long			sk_sndtimeo;
	struct timer_list	sk_timer;
	__u32			sk_priority;
	__u32			sk_mark;
	u32			sk_pacing_rate; /* bytes per second */
	u32			sk_max_pacing_rate;
	struct page_frag	sk_frag;
	netdev_features_t	sk_route_caps;
	netdev_features_t	sk_route_nocaps;
	netdev_features_t	sk_route_forced_caps;
	int			sk_gso_type;
	unsigned int		sk_gso_max_size;
	gfp_t			sk_allocation;
	__u32			sk_txhash;

	/*
	 * Because of non atomicity rules, all
	 * changes are protected by socket lock.
	 */
	unsigned int		__sk_flags_offset[0];
#ifdef __BIG_ENDIAN_BITFIELD
#define SK_FL_PROTO_SHIFT  16
#define SK_FL_PROTO_MASK   0x00ff0000

#define SK_FL_TYPE_SHIFT   0
#define SK_FL_TYPE_MASK    0x0000ffff
#else
#define SK_FL_PROTO_SHIFT  8
#define SK_FL_PROTO_MASK   0x0000ff00

#define SK_FL_TYPE_SHIFT   16
#define SK_FL_TYPE_MASK    0xffff0000
#endif

	unsigned int		sk_padding : 1,
				sk_kern_sock : 1,
				sk_no_check_tx : 1,
				sk_no_check_rx : 1,
				sk_userlocks : 4,
				sk_protocol  : 8,
				sk_type      : 16;
#define SK_PROTOCOL_MAX U8_MAX
	u16			sk_gso_max_segs;
	u8			sk_pacing_shift;
	unsigned long	        sk_lingertime;
	struct proto		*sk_prot_creator;
	rwlock_t		sk_callback_lock;
	int			sk_err,
				sk_err_soft;
	u32			sk_ack_backlog;
	u32			sk_max_ack_backlog;
	kuid_t			sk_uid;
	struct pid		*sk_peer_pid;
	const struct cred	*sk_peer_cred;
	long			sk_rcvtimeo;
	ktime_t			sk_stamp;
#if BITS_PER_LONG==32
	seqlock_t		sk_stamp_seq;
#endif
	u16			sk_tsflags;
	u8			sk_shutdown;
	u32			sk_tskey;
	atomic_t		sk_zckey;

	u8			sk_clockid;
	u8			sk_txtime_deadline_mode : 1,
				sk_txtime_report_errors : 1,
				sk_txtime_unused : 6;

	struct socket		*sk_socket;
	void			*sk_user_data;
#ifdef CONFIG_SECURITY
	void			*sk_security;
#endif
	struct sock_cgroup_data	sk_cgrp_data;
	struct mem_cgroup	*sk_memcg;
	void			(*sk_state_change)(struct sock *sk);
	void			(*sk_data_ready)(struct sock *sk);
	void			(*sk_write_space)(struct sock *sk);
	void			(*sk_error_report)(struct sock *sk);
	int			(*sk_backlog_rcv)(struct sock *sk,
						  struct sk_buff *skb);
#ifdef CONFIG_SOCK_VALIDATE_XMIT
	struct sk_buff*		(*sk_validate_xmit_skb)(struct sock *sk,
							struct net_device *dev,
							struct sk_buff *skb);
#endif
	void                    (*sk_destruct)(struct sock *sk);
	struct sock_reuseport __rcu	*sk_reuseport_cb;
	struct rcu_head		sk_rcu;
};

