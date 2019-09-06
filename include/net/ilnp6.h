/*
* This file is provided under a dual BSD/GPLv2 license.  When using or
* redistributing this file, you may do so under either license.
* All contributions have to be made under both licenses.
*/

/*
* BSD LICENSE
*
* Copyright (C) 2019, the authors:
* Saleem Bhatti (ILNP Project Lead) ilnp-admin@st-andrews.ac.uk,
* Ryo Yanagida, Khawar Shehzad, Ditchaphong Phoomikiattisak.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*/

/*
* GPL LICENSE SUMMARY
*
* Copyright (C) 2019, the authors:
* Saleem Bhatti (ILNP Project Lead) ilnp-admin@st-andrews.ac.uk,
* Ryo Yanagida, Khawar Shehzad, Ditchaphong Phoomikiattisak.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of version 2 of the GNU General Public License as
* published by the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but
* WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* General Public License for more details.
*
* The full GNU General Public License is included in this distribution
* in the file called "ilnp-gplv2.txt".
*
*/


#ifndef _ILNP_H
#define _ILNP_H

#include <linux/types.h>
#include <linux/in6.h>
#include <linux/list.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/icmpv6.h>
#include <linux/hashtable.h>
#include <linux/timer.h>

/* Flags for L64 in ILCC
 */
#define L64_VALID 	1
#define L64_ACTIVE	2	// valid and currently used
#define L64_AGED	3	// old L64, In overlap area, not accept packet but no handoff when get RA
#define L64_EXPIRED	4	// old L64 handoff when get RA (move back to previous network)

/*ICMPv6 type for LU*/
#define ILNP6_LOCATOR_UPDATE 156
//#define ILNP6_LU_INFO 16842752	//01 01 00 00: number of locator = 1, and it is LU (1)
//#define ILNP6_LU_ACK_INFO 16908288 	//01 02 00 00: number of locator = 1, and it is LU-ACK (2)

#define L64_DEFAULT_PREC 10
#define L64_DEFAULT_LIFETIME 30 	//Life time for each L64 value 30 sec
#define CACHE_TIME_OUT 1800  		//ILNP entry timeout, 30 mins for now
#define ILNP_SESSION_TIMEOUT 30  	//ILNP session timeout, 30 sec for now

//#define MAX_RET_TIMEOUT 32  		/*Maximun retransmission timeout (same as IPv6 Binding Update - rfc3775 section 12)*/
#define LU_RET_TIMEOUT 1000		// retransmission timeout for LU, now is set to 1 sec (1000 ms)
#define MAX_LU_SENT 7		// maximum number of retransmission, before consider it as handoff failed

#define ILNP_HASH_BITS 8	// number of bit that will be used for hash table of ilcc and lu_table (8 bits = 256 entries)

#define ILNP_NONCE_32 4		// number of bit for 32-bit nonce value
#define ILNP_NONCE_96 12	// number of bit for 96-bit nonce value

/* structure for ILNPv6 address cache
 * added by dp32 */
struct ilnp_cache_entry {
  	uint64_t		l64;
	uint64_t		nid;
	uint32_t		l64_prec;
	unsigned long		timestamp;
};


struct ilnp_addr_cache {
	struct list_head		list;
	struct ilnp_cache_entry		*entry;

};

/* Structure for ILCC
 */

struct l64_info {
      struct list_head	list;
      uint64_t		l64;
      uint32_t		prec;
      uint32_t		flag;
      //unsigned long	timestamp;
      uint32_t		lifetime;
      //int		lu_sent;
      //int		wait_for_ack;
      struct timer_list	timer;
};

struct ilnp_ilcc {
      struct list_head	list;
      uint64_t		nid;
      struct l64_info	*l64_info;
      uint64_t		nid_local;
      struct l64_info	*l64_local;
      char		ifname[IFNAMSIZ]; 		// interface that is currently talking to this node
      uint32_t		nonce_local;
      uint32_t		nonce_cn;
      struct timer_list	session_timer;			// to clear nonce value after session timeout
};

/* Hash table to store information of ILCC*/
struct ilcc_table {
      struct hlist_node		hlist;
      struct list_head		ilcc_node;
      struct ilnp_ilcc		*ilcc_info;
};

/*Structure for LU message*/
struct lu_data {
      uint64_t		l64;
      uint32_t		prec;
      uint32_t		lifetime;

};

struct lu_msg {
      /* ICMPv6 header */
      __u8		icmp6_type;
      __u8		icmp6_code;
      __sum16		icmp6_cksum;
      __u8		num_loc;
      __u8		opt;
      __be16		reserved;
      /* Data */
      uint64_t		l64;
      uint32_t		prec;
      uint32_t		lifetime;
};

/*Structure of LU message that has been sent and still wait for LU-ACK
  We use this information to perform retransmission */
struct lu_info {
      uint64_t			cn_nid;
      uint64_t			l64;
      char			ifname[IFNAMSIZ];
      struct in6_addr		daddr;
      struct in6_addr 		saddr;
      uint32_t			nonce;
      //unsigned long		timestamp;
      struct timer_list		timer;
      uint32_t			counter;
};

/* Hash table to store information of LU*/
struct lu_table {
      struct hlist_node		hlist;
      struct list_head		lu_node;
      struct lu_info		*lu_info;
};

/* Nonce option in IPv6 destination option header*/
struct ilnp6_nonceopt {
      __u8		type;
      __u8		length;
      uint32_t		nonce;
} __attribute__((packed));	// no auto-padding

extern int 	ilnp_disabled(void);
extern int 	ilnp6_init(void);
extern void	ilnp6_cleanup(void);
extern int 	ilnp6_add_addr(struct ilnp_cache_entry *new_en);
extern int 	ilnp6_del_addr(struct ilnp_cache_entry *exp_en);
extern void	print_addr_cache(void);
extern int 	in_ilcc(struct in6_addr *address);
extern int 	is_ilnp6(struct in6_addr *address);
extern int	ilnp6_send(struct sk_buff *skb, struct in6_addr *saddr, struct in6_addr *daddr, unsigned char proto);
extern int 	ilnp6_rcv(struct sk_buff *skb);
extern int	ilnp6_rcv_ra(struct net_device *dev, struct in6_addr *prefix, __u32 lifetime);
extern int	rcv_lu(struct sk_buff *skb);
extern int 	ilnp6_check_nonce(struct sk_buff *skb);
extern struct net_device *  ilnp6_check_oif(struct net_device *dev);

#endif /*_ILNP_H*/
