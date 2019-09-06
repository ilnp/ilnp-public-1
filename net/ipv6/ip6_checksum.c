/*
 * ILNP-specific modifications Copyright (C) 2019, the authors:
 * Saleem Bhatti (ILNP Project Lead) ilnp-admin@st-andrews.ac.uk,
 * Ryo Yanagida, Khawar Shehzad, Ditchaphong Phoomikiattisak.
 */

#include <net/ip.h>
#include <net/udp.h>
#include <net/udplite.h>
#include <asm/checksum.h>
#include <net/ilnp6.h>

#ifndef _HAVE_ARCH_IPV6_CSUM
__sum16 csum_ipv6_magic(const struct in6_addr *saddr,
			const struct in6_addr *daddr,
			__u32 len, __u8 proto, __wsum csum)
{

	int carry;
	__u32 ulen;
	__u32 uproto;
	__u32 sum = (__force u32)csum;

	sum += (__force u32)saddr->s6_addr32[0];
	carry = (sum < (__force u32)saddr->s6_addr32[0]);
	sum += carry;

	sum += (__force u32)saddr->s6_addr32[1];
	carry = (sum < (__force u32)saddr->s6_addr32[1]);
	sum += carry;

	sum += (__force u32)saddr->s6_addr32[2];
	carry = (sum < (__force u32)saddr->s6_addr32[2]);
	sum += carry;

	sum += (__force u32)saddr->s6_addr32[3];
	carry = (sum < (__force u32)saddr->s6_addr32[3]);
	sum += carry;

	sum += (__force u32)daddr->s6_addr32[0];
	carry = (sum < (__force u32)daddr->s6_addr32[0]);
	sum += carry;

	sum += (__force u32)daddr->s6_addr32[1];
	carry = (sum < (__force u32)daddr->s6_addr32[1]);
	sum += carry;

	sum += (__force u32)daddr->s6_addr32[2];
	carry = (sum < (__force u32)daddr->s6_addr32[2]);
	sum += carry;

	sum += (__force u32)daddr->s6_addr32[3];
	carry = (sum < (__force u32)daddr->s6_addr32[3]);
	sum += carry;

	ulen = (__force u32)htonl((__u32) len);
	sum += ulen;
	carry = (sum < ulen);
	sum += carry;

	uproto = (__force u32)htonl(proto);
	sum += uproto;
	carry = (sum < uproto);
	sum += carry;

	return csum_fold((__force __wsum)sum);
}
EXPORT_SYMBOL(csum_ipv6_magic);
#endif

int udp6_csum_init(struct sk_buff *skb, struct udphdr *uh, int proto)
{
        pr_debug("[ILNP] ==> In udp6_csum_init()\n");
	int err;
	int pseudo;
	uint64_t l64, l64_local; /* ilnp6*/	

	UDP_SKB_CB(skb)->partial_cov = 0;
	UDP_SKB_CB(skb)->cscov = skb->len;

	/**** ILNP Start ****/
	pr_debug("[ILNP] Calculate UDP checksum\n");

        if (skb->is_ilnp == 1) {

                pr_debug("[ILNP] Receive UDP from ILNP host\n");

                // Backup L64 value
                memcpy(&l64, &ipv6_hdr(skb)->daddr.s6_addr[0], sizeof(ipv6_hdr(skb)->daddr.s6_addr[0])*8);
                memcpy(&l64_local, &ipv6_hdr(skb)->saddr.s6_addr[0], sizeof(ipv6_hdr(skb)->saddr.s6_addr[0])*8);

                // Remove L64 from saddr and daddr, so only NID will be used for checksum calculation
                memset(&ipv6_hdr(skb)->daddr.s6_addr[0], 0, sizeof(ipv6_hdr(skb)->daddr.s6_addr[0])*8);
                memset(&ipv6_hdr(skb)->saddr.s6_addr[0], 0, sizeof(ipv6_hdr(skb)->saddr.s6_addr[0])*8);
        }
	/**** ILNP Finish ****/
	
	if (proto == IPPROTO_UDPLITE) {
		err = udplite_checksum_init(skb, uh);
		if (err)
			return err;
	}

	/* To support RFC 6936 (allow zero checksum in UDP/IPV6 for tunnels)
	 * we accept a checksum of zero here. When we find the socket
	 * for the UDP packet we'll check if that socket allows zero checksum
	 * for IPv6 (set by socket option).
	 *
	 * Note, we are only interested in != 0 or == 0, thus the
	 * force to int.
	 */
	pseudo =  (__force int)skb_checksum_init_zero_check(skb, proto, uh->check,
							 ip6_compute_pseudo);
	/**** ILNP Start ****/
	if (skb->is_ilnp == 1) {
                // Put L64 back to saddr and daddr
                memcpy(&ipv6_hdr(skb)->daddr.s6_addr[0], &l64, sizeof(ipv6_hdr(skb)->daddr.s6_addr[0])*8);
                memcpy(&ipv6_hdr(skb)->saddr.s6_addr[0], &l64_local, sizeof(ipv6_hdr(skb)->saddr.s6_addr[0])*8);
        }
	/**** ILNP Finish ****/

	return pseudo;
}
EXPORT_SYMBOL(udp6_csum_init);

/* Function to set UDP checksum for an IPv6 UDP packet. This is intended
 * for the simple case like when setting the checksum for a UDP tunnel.
 */
void udp6_set_csum(bool nocheck, struct sk_buff *skb,
		   const struct in6_addr *saddr,
		   const struct in6_addr *daddr, int len)
{
	struct udphdr *uh = udp_hdr(skb);

	if (nocheck)
		uh->check = 0;
	else if (skb_is_gso(skb))
		uh->check = ~udp_v6_check(len, saddr, daddr, 0);
	else if (skb->ip_summed == CHECKSUM_PARTIAL) {
		uh->check = 0;
		uh->check = udp_v6_check(len, saddr, daddr, lco_csum(skb));
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
	} else {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		uh->check = ~udp_v6_check(len, saddr, daddr, 0);
	}
}
EXPORT_SYMBOL(udp6_set_csum);
