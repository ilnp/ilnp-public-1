/*
 *	IPv6 input
 *	Linux INET6 implementation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Ian P. Morris		<I.P.Morris@soton.ac.uk>
 *
 *	Based in linux/net/ipv4/ip_input.c
 *
 * ILNP-specific modifications Copyright (C) 2019, the authors:
 * Saleem Bhatti (ILNP Project Lead) ilnp-admin@st-andrews.ac.uk,
 * Ryo Yanagida, Khawar Shehzad, Ditchaphong Phoomikiattisak.
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
/* Changes
 *
 *	Mitsuru KANDA @USAGI and
 *	YOSHIFUJI Hideaki @USAGI: Remove ipv6_parse_exthdrs().
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/in6.h>
#include <linux/icmpv6.h>
#include <linux/mroute6.h>
#include <linux/slab.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>

#include <net/sock.h>
#include <net/snmp.h>

#include <net/ipv6.h>
#include <net/protocol.h>
#include <net/transp_v6.h>
#include <net/rawv6.h>
#include <net/ndisc.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/xfrm.h>
#include <net/inet_ecn.h>
#include <net/dst_metadata.h>
#include <net/ilnp6.h>

int ip6_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	/* if ingress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip6_rcv(skb);
	if (!skb){
		pr_debug("[ip6_input.c] ip6_rcv_finish(): !skb after l3mdev_ip6_rcv(skb) returning NET_RX_SUCCESS\n");
		return NET_RX_SUCCESS;
	}

	if (net->ipv4.sysctl_ip_early_demux && !skb_dst(skb) && skb->sk == NULL) {
		const struct inet6_protocol *ipprot;
		pr_debug("[ip6_input.c] ip6_rcv_finish(): (ipv4.sysctl_ip_early_demux && !skb_dst(skb) && skb->sk == NULL) == true. about to do rcu_dereference(inet6_protos[ipv6_hdr(skb)->nexthdr])\n");
		ipprot = rcu_dereference(inet6_protos[ipv6_hdr(skb)->nexthdr]);
		if (ipprot && ipprot->early_demux){
			pr_debug("[ip6_input.c] ip6_rcv_finish(): ipprot && ipprot -> early_demux), calling early_demux(skb)\n");
			ipprot->early_demux(skb);
		}
	}
	if (!skb_valid_dst(skb)){
		pr_debug("[ip6_input.c] ip6_rcv_finish: !skb_valid_dst(skb) == true, about to do ip6_route_input(skb).\n");
		ip6_route_input(skb);
		if(skb->_skb_refdst)
			pr_debug("[ip6_input.c] ip6_rcv_finish: skb->_skb_refdst = %lx \n", skb->_skb_refdst);
	}
	pr_debug("[ip6_input.c] ip6_rcv_finish: about to return dst_input(skb)\n");
	if(skb->_skb_refdst)
		pr_debug("[ip6_input.c] (struct dst_entry) skb->_skb_refdst->input() = %pF\n",((struct dst_entry *)skb->_skb_refdst)->input);
	return dst_input(skb);
}

int ipv6_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	const struct ipv6hdr *hdr;
	u32 pkt_len;
	struct inet6_dev *idev;
	struct net *net = dev_net(skb->dev);

	if (skb->pkt_type == PACKET_OTHERHOST) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	rcu_read_lock();

	idev = __in6_dev_get(skb->dev);

	__IP6_UPD_PO_STATS(net, idev, IPSTATS_MIB_IN, skb->len);

	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL ||
	    !idev || unlikely(idev->cnf.disable_ipv6)) {
		__IP6_INC_STATS(net, idev, IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	memset(IP6CB(skb), 0, sizeof(struct inet6_skb_parm));

	/*
	 * Store incoming device index. When the packet will
	 * be queued, we cannot refer to skb->dev anymore.
	 *
	 * BTW, when we send a packet for our own local address on a
	 * non-loopback interface (e.g. ethX), it is being delivered
	 * via the loopback interface (lo) here; skb->dev = loopback_dev.
	 * It, however, should be considered as if it is being
	 * arrived via the sending interface (ethX), because of the
	 * nature of scoping architecture. --yoshfuji
	 */
	IP6CB(skb)->iif = skb_valid_dst(skb) ? ip6_dst_idev(skb_dst(skb))->dev->ifindex : dev->ifindex;

	if (unlikely(!pskb_may_pull(skb, sizeof(*hdr))))
		goto err;

	hdr = ipv6_hdr(skb);

	if (hdr->version != 6)
		goto err;

	__IP6_ADD_STATS(net, idev,
			IPSTATS_MIB_NOECTPKTS +
				(ipv6_get_dsfield(hdr) & INET_ECN_MASK),
			max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));
	/*
	 * RFC4291 2.5.3
	 * A packet received on an interface with a destination address
	 * of loopback must be dropped.
	 */
	if (!(dev->flags & IFF_LOOPBACK) &&
	    ipv6_addr_loopback(&hdr->daddr))
		goto err;

	/* RFC4291 Errata ID: 3480
	 * Interface-Local scope spans only a single interface on a
	 * node and is useful only for loopback transmission of
	 * multicast.  Packets with interface-local scope received
	 * from another node must be discarded.
	 */
	if (!(skb->pkt_type == PACKET_LOOPBACK ||
	      dev->flags & IFF_LOOPBACK) &&
	    ipv6_addr_is_multicast(&hdr->daddr) &&
	    IPV6_ADDR_MC_SCOPE(&hdr->daddr) == 1)
		goto err;

	/* If enabled, drop unicast packets that were encapsulated in link-layer
	 * multicast or broadcast to protected against the so-called "hole-196"
	 * attack in 802.11 wireless.
	 */
	if (!ipv6_addr_is_multicast(&hdr->daddr) &&
	    (skb->pkt_type == PACKET_BROADCAST ||
	     skb->pkt_type == PACKET_MULTICAST) &&
	    idev->cnf.drop_unicast_in_l2_multicast)
		goto err;

	/* RFC4291 2.7
	 * Nodes must not originate a packet to a multicast address whose scope
	 * field contains the reserved value 0; if such a packet is received, it
	 * must be silently dropped.
	 */
	if (ipv6_addr_is_multicast(&hdr->daddr) &&
	    IPV6_ADDR_MC_SCOPE(&hdr->daddr) == 0)
		goto err;

	/*
	 * RFC4291 2.7
	 * Multicast addresses must not be used as source addresses in IPv6
	 * packets or appear in any Routing header.
	 */
	if (ipv6_addr_is_multicast(&hdr->saddr))
		goto err;

	skb->transport_header = skb->network_header + sizeof(*hdr);
	IP6CB(skb)->nhoff = offsetof(struct ipv6hdr, nexthdr);

	pkt_len = ntohs(hdr->payload_len);

	/* pkt_len may be zero if Jumbo payload option is present */
	if (pkt_len || hdr->nexthdr != NEXTHDR_HOP) {
		pr_debug("[ip6_input.c] ipv6_rcv(): pkt_len: %x || hdr->nexthdr != NEXTHDR_HOP \n", pkt_len);
		if (pkt_len + sizeof(struct ipv6hdr) > skb->len) {
			__IP6_INC_STATS(net,
					idev, IPSTATS_MIB_INTRUNCATEDPKTS);
			pr_debug("[ip6_input.c] ipv6_rcv(): pkt_len: %x + sizeof ipv6hdr > skb->len: %x ; drop;\n", pkt_len, skb->len);
			goto drop;
		}
		if (pskb_trim_rcsum(skb, pkt_len + sizeof(struct ipv6hdr))) {
			__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);
			pr_debug("[ip6_input.c] ipv6_rcv(): pskb_trim_rcsum... drop; \n");
			goto drop;
		}
		pr_debug("[ip6_input.c] ipv6_rcv(): about to do hdr=ipv6_hdr(skb) skb->dev: %s\n",skb->dev->name);
		hdr = ipv6_hdr(skb);
	}

	if (hdr->nexthdr == NEXTHDR_HOP) {
		if (ipv6_parse_hopopts(skb) < 0) {
			__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);
			rcu_read_unlock();
			pr_debug("[ip6_input.c] ipv6_rcv(): return NET_RX_DROP;\n");
			return NET_RX_DROP;
		}
	}

	rcu_read_unlock();

	/* Must drop socket now because of tproxy. */
	skb_orphan(skb);
	pr_debug("[ip6_input.c] ipv6_rcv(): about to do NF_HOOK after skb_orphan(skb)\n");
	return NF_HOOK(NFPROTO_IPV6, NF_INET_PRE_ROUTING,
		       net, NULL, skb, dev, NULL,
		       ip6_rcv_finish);
err:
	pr_debug("[ip6_input.c] ipv6_rcv(): err:!\n");
	__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);
drop:
	rcu_read_unlock();
	kfree_skb(skb);
	return NET_RX_DROP;
}

/*
 *	Deliver the packet to the host
 */


static int ip6_input_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	const struct inet6_protocol *ipprot;
	struct inet6_dev *idev;
	unsigned int nhoff;
	int nexthdr;
	bool raw;
	bool have_final = false;
	const struct ipv6hdr *header; // [ILNP]

	/*
	 *	Parse extension headers
	 */

	/* [ILNP] - Prep
         */
	rcu_read_lock();
	skb->has_nonce = 0;
	skb->is_ilnp = 0;
	pr_debug("[ILNP] Receive a Packet from %s\n", skb->dev->name);
/* [ILNP] Prep Finish */

resubmit:
	idev = ip6_dst_idev(skb_dst(skb));

	/*ILNP - start*/
	header = ipv6_hdr(skb);
	/* Check if it is an ILNPv6 packet
	 * This is done by check if the packet has nonce option
	 */
	pr_debug("[ILNP] Prepare to process the packet\n");

	if (skb->has_nonce == 1 && skb->is_ilnp == 1) {
		pr_debug("[ILNP] Nonce option has been checked, forward to Transport protocol\n");
	}

	else {
		if (header->nexthdr == IPPROTO_DSTOPTS) {
			struct ilnp6_nonceopt *nonceopt;
			nonceopt = (struct ilnp6_nonceopt *)(skb_network_header(skb) + skb_network_header_len(skb) + 2);
			pr_debug("[ILNP] Check destination option type: %d\n", nonceopt->type);

			if (nonceopt->type == 0x8B) {
				int err;
				pr_debug("[ILNP] Receive ILNPv6 Packet from %s\n", skb->dev->name);
				skb->is_ilnp = 1;
				err = ilnp6_rcv(skb);

				if (err) {
					pr_debug("[ILNP] Discard packet\n");
					goto discard;
				}
			}
		}else{
			pr_debug("[ip6_input.c] ip6_input_finish(): if-case: !header->nexthdr == IPPROTO_DSOPTS\n");
		}
	}

	/*ILNP - finish*/

	if (!pskb_pull(skb, skb_transport_offset(skb)))
		goto discard;
	nhoff = IP6CB(skb)->nhoff;
	nexthdr = skb_network_header(skb)[nhoff];

resubmit_final:
	raw = raw6_local_deliver(skb, nexthdr);
	ipprot = rcu_dereference(inet6_protos[nexthdr]);
	if (ipprot) {
		int ret;

		if (have_final) {
			if (!(ipprot->flags & INET6_PROTO_FINAL)) {
				/* Once we've seen a final protocol don't
				 * allow encapsulation on any non-final
				 * ones. This allows foo in UDP encapsulation
				 * to work.
				 */
				goto discard;
			}
		} else if (ipprot->flags & INET6_PROTO_FINAL) {
			const struct ipv6hdr *hdr;

			/* Only do this once for first final protocol */
			have_final = true;

			/* Free reference early: we don't need it any more,
			   and it may hold ip_conntrack module loaded
			   indefinitely. */
			nf_reset(skb);

			skb_postpull_rcsum(skb, skb_network_header(skb),
					   skb_network_header_len(skb));
			hdr = ipv6_hdr(skb);
			if (ipv6_addr_is_multicast(&hdr->daddr) &&
			    !ipv6_chk_mcast_addr(skb->dev, &hdr->daddr,
			    &hdr->saddr) &&
			    !ipv6_is_mld(skb, nexthdr, skb_network_header_len(skb)))
				goto discard;
		}
		if (!(ipprot->flags & INET6_PROTO_NOPOLICY) &&
		    !xfrm6_policy_check(NULL, XFRM_POLICY_IN, skb))
			goto discard;

		ret = ipprot->handler(skb);
		if (ret > 0) {
			if (ipprot->flags & INET6_PROTO_FINAL) {
				/* Not an extension header, most likely UDP
				 * encapsulation. Use return value as nexthdr
				 * protocol not nhoff (which presumably is
				 * not set by handler).
				 */
				nexthdr = ret;
				goto resubmit_final;
			} else {
				goto resubmit;
			}
		} else if (ret == 0) {
			__IP6_INC_STATS(net, idev, IPSTATS_MIB_INDELIVERS);
		}
	} else {
		if (!raw) {
			if (xfrm6_policy_check(NULL, XFRM_POLICY_IN, skb)) {
				__IP6_INC_STATS(net, idev,
						IPSTATS_MIB_INUNKNOWNPROTOS);
				icmpv6_send(skb, ICMPV6_PARAMPROB,
					    ICMPV6_UNK_NEXTHDR, nhoff);
			}
			kfree_skb(skb);
		} else {
			__IP6_INC_STATS(net, idev, IPSTATS_MIB_INDELIVERS);
			consume_skb(skb);
		}
	}
	rcu_read_unlock();
	return 0;

discard:
	__IP6_INC_STATS(net, idev, IPSTATS_MIB_INDISCARDS);
	rcu_read_unlock();
	kfree_skb(skb);
	return 0;
}


int ip6_input(struct sk_buff *skb)
{
	return NF_HOOK(NFPROTO_IPV6, NF_INET_LOCAL_IN,
		       dev_net(skb->dev), NULL, skb, skb->dev, NULL,
		       ip6_input_finish);
}
EXPORT_SYMBOL_GPL(ip6_input);

int ip6_mc_input(struct sk_buff *skb)
{
	const struct ipv6hdr *hdr;
	bool deliver;

	__IP6_UPD_PO_STATS(dev_net(skb_dst(skb)->dev),
			 ip6_dst_idev(skb_dst(skb)), IPSTATS_MIB_INMCAST,
			 skb->len);

	hdr = ipv6_hdr(skb);
	deliver = ipv6_chk_mcast_addr(skb->dev, &hdr->daddr, NULL);

#ifdef CONFIG_IPV6_MROUTE
	/*
	 *      IPv6 multicast router mode is now supported ;)
	 */
	if (dev_net(skb->dev)->ipv6.devconf_all->mc_forwarding &&
	    !(ipv6_addr_type(&hdr->daddr) &
	      (IPV6_ADDR_LOOPBACK|IPV6_ADDR_LINKLOCAL)) &&
	    likely(!(IP6CB(skb)->flags & IP6SKB_FORWARDED))) {
		/*
		 * Okay, we try to forward - split and duplicate
		 * packets.
		 */
		struct sk_buff *skb2;
		struct inet6_skb_parm *opt = IP6CB(skb);

		/* Check for MLD */
		if (unlikely(opt->flags & IP6SKB_ROUTERALERT)) {
			/* Check if this is a mld message */
			u8 nexthdr = hdr->nexthdr;
			__be16 frag_off;
			int offset;

			/* Check if the value of Router Alert
			 * is for MLD (0x0000).
			 */
			if (opt->ra == htons(IPV6_OPT_ROUTERALERT_MLD)) {
				deliver = false;

				if (!ipv6_ext_hdr(nexthdr)) {
					/* BUG */
					goto out;
				}
				offset = ipv6_skip_exthdr(skb, sizeof(*hdr),
							  &nexthdr, &frag_off);
				if (offset < 0)
					goto out;

				if (ipv6_is_mld(skb, nexthdr, offset))
					deliver = true;

				goto out;
			}
			/* unknown RA - process it normally */
		}

		if (deliver)
			skb2 = skb_clone(skb, GFP_ATOMIC);
		else {
			skb2 = skb;
			skb = NULL;
		}

		if (skb2) {
			ip6_mr_input(skb2);
		}
	}
out:
#endif
	if (likely(deliver))
		ip6_input(skb);
	else {
		/* discard */
		kfree_skb(skb);
	}

	return 0;
}
