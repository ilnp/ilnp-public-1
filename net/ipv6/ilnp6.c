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

#include <linux/slab.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/sched.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <net/ilnp6.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <linux/if_ether.h>
#include <drm/radeon_drm.h>
#include <net/ndisc.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/xfrm.h>
#include <linux/etherdevice.h>


/* Structure for address cache*/
static struct ilnp_addr_cache *addr_cache;
static struct kmem_cache *addr_cache_kmem;

static struct task_struct *thread1;		// kernel thread to monitor the addres cache
static struct sock *nl_sk = NULL;		// netlink socket for receiving ILNP address from /etc/hosts file

/* Structure for ILCC*/
static DEFINE_HASHTABLE(ilcc_info_table, ILNP_HASH_BITS);
static struct kmem_cache *ilcc_kmem;
static struct kmem_cache *l64_kmem;

/* Structure for LU cache*/
static DEFINE_HASHTABLE(lu_info_table, ILNP_HASH_BITS);
static struct kmem_cache *lu_cache_kmem;

/*For retransmission*/
struct net_device *cur_dev;
struct net_device *new_dev;
struct in6_addr *cur_prefix;

// DEFINE_SPINLOCK(addr_cache_lock);
//DEFINE_SPINLOCK(ilcc_lock);
//DEFINE_SPINLOCK(lu_table_lock);

/*Virtual interface for ILNP operation*/
struct net_device *ilnp_vir_dev;

/* Home L64, this used to bind to any upper layer protocols/applications that bind to IP addrress*/
uint64_t l64_home;

/* Handoff mode: Soft(0) or hard(1)*/
static int handoff_mode;

/* Delay before sending LU after receive prefix*/
static int lu_delay;

/* For completely disable ILNP when MIP is in used*/
static int disable_ilnp;

/* Sysctl variable for handoff mode and lu delay time*/
/* Sysctl variable for handoff mode*/
static struct ctl_table_header *ilnp_table_header;

static struct ctl_table ilnp_table[] = {
   { .procname	= "handoff_mode",
     .data	= &handoff_mode,
     .maxlen	= sizeof(int),
     .mode	= 0644,
     .proc_handler = &proc_dointvec },
   {.procname	= "lu_delay",
     .data	= &lu_delay,
     .maxlen	= sizeof(int),
     .mode	= 0644,
     .proc_handler = &proc_dointvec},
   {.procname	= "disable",
     .data	= &disable_ilnp,
     .maxlen	= sizeof(int),
     .mode	= 0644,
     .proc_handler = &proc_dointvec},
   {}
};

static struct ctl_table ilnp_dir_table[] = {
   { .procname	= "ilnp6",
     .mode	= 0555,
     .child	= ilnp_table },
   {}
};

static struct ctl_table ilnp_root_table[] = {
   { .procname 	= "net",
     .mode	= 0555,
     .child	= ilnp_dir_table },
   {}
};


int send_lu(uint64_t l64, struct net_device *dev, struct in6_addr *dst, struct in6_addr *src, int is_ack, uint32_t nonce);

int ilnp_disabled() {

	if (disable_ilnp == 1)
		return 1;
	else
		return 0;

}

/* Add new ILNP adress to address cache */
int ilnp6_add_addr(struct ilnp_cache_entry *new_en)
{
	struct ilnp_addr_cache *tmp_addr, *element;
	int dup=0;
	tmp_addr = kmem_cache_zalloc(addr_cache_kmem, GFP_ATOMIC);
	tmp_addr->entry = kmalloc(sizeof(struct ilnp_cache_entry), GFP_ATOMIC);
	tmp_addr->entry->l64 = new_en->l64;
	tmp_addr->entry->nid = new_en->nid;
	tmp_addr->entry->l64_prec = new_en->l64_prec;
	tmp_addr->entry->timestamp = jiffies;

	//spin_lock(&addr_cache_lock);
	list_for_each_entry(element, &addr_cache->list, list) {
	   if (tmp_addr->entry->l64 == element->entry->l64 &&
		tmp_addr->entry->nid == element->entry->nid) {
	      dup = 1;
	      pr_debug( "[ilnp6.c] ilnp6_add_addr(): Already in cache, update timestamp\n");
	      element->entry->timestamp = jiffies;
	      break;
	   }

	}

	if (!dup) {
	    pr_debug( "[ilnp6.c] ilnp6_add_addr(): Add address to cache\n");
	    list_add_tail(&tmp_addr->list, &addr_cache->list);
	}
	print_addr_cache();
	//spin_unlock(&addr_cache_lock);

	return 0;
}

int ilnp6_del_addr(struct ilnp_cache_entry *exp_en)
{
  	struct ilnp_addr_cache *element, *next;

	pr_debug( "[ilnp6.c] ilnp6_del_addr(): Delete an entry\n");

	//spin_lock(&addr_cache_lock);
	list_for_each_entry_safe(element, next, &addr_cache->list, list) {
	   if (exp_en->l64 == element->entry->l64 &&
		exp_en->nid == element->entry->nid) {
	      list_del(&element->list);
	      kmem_cache_free(addr_cache_kmem, element);
	   }
	}
	//spin_unlock(&addr_cache_lock);

	return 0;

}

void print_ilcc(void)
{
	struct ilcc_table *entry;
	struct l64_info *l64_entry;
	int i;

	pr_debug( "[ilnp6.c] print_ilcc(): Address in cache:\n");


	hash_for_each(ilcc_info_table, i, entry, hlist) {
	    pr_debug( "[ilnp6.c] ------------------------------------------\n");
	    pr_debug( "[ilnp6.c]          CNs                    \n");
	    pr_debug( "[ilnp6.c] ------------------------------------------\n");

	    pr_debug( "[ilnp6.c] Current interface: %s, NID: %x, Nonce: %u, Locator info:\n",
		   entry->ilcc_info->ifname, htonl(entry->ilcc_info->nid), entry->ilcc_info->nonce_cn);
	    list_for_each_entry(l64_entry, &entry->ilcc_info->l64_info->list, list) {
		  pr_debug( "[ilnp6.c] L64: %x prec: %d flag: %d\n",
			 htonl(l64_entry->l64), l64_entry->prec, l64_entry->flag);

	    }
	    pr_debug( "[ilnp6.c] ------------------------------------------\n");
	    pr_debug( "[ilnp6.c]          Local                  \n");
	    pr_debug( "[ilnp6.c] ------------------------------------------\n");
	    pr_debug( "[ilnp6.c] NID: %x, Nonce: %u, Locator info:\n", htonl(entry->ilcc_info->nid_local), entry->ilcc_info->nonce_local);
	    list_for_each_entry(l64_entry, &entry->ilcc_info->l64_local->list, list) {
		  pr_debug( "[ilnp6.c] L64: %x prec: %d flag: %d, lifetime: %d\n",
			 htonl(l64_entry->l64), l64_entry->prec, l64_entry->flag, l64_entry->lifetime);

	    }
	    pr_debug( "[ilnp6.c] ------------------------------------------\n");

	}


}

void print_addr_cache(void)
{
	struct ilnp_addr_cache *entry;

  pr_debug( "[ilnp6.c] print_addr_cache():\n \
             [ilnp6.c] ------------------------------------------\n");
	pr_debug( "[ilnp6.c] Address in cache:\n");
	list_for_each_entry(entry, &addr_cache->list, list) {
	    pr_debug( "[ilnp6.c] L64: %x, NID: %x, prec: %d, timestamp: %ld\n",
		   htonl(entry->entry->l64), htonl(entry->entry->nid),
		   entry->entry->l64_prec, entry->entry->timestamp );
	    pr_debug( "[ilnp6.c] ------------------------------------------\n");

	}
	pr_debug( "[ilnp6.c] ------------------------------------------\n");

}

void print_lu_table(void)
{
	struct lu_table *lu_entry;
	int i;
	pr_debug( "[ilnp6.c] print_lu_table(): \n \
              [ilnp6.c] ------------------------------------------\n");
	pr_debug( "[ilnp6.c] LU in cache:\n");
	hash_for_each(lu_info_table, i, lu_entry, hlist) {
	    pr_debug( "[ilnp6.c] prefix: %x, dest NID: %x, counter: %d\n",
		   htonl(lu_entry->lu_info->l64), htonl(lu_entry->lu_info->cn_nid),
		   lu_entry->lu_info->counter);
	    pr_debug( "[ilnp6.c] ------------------------------------------\n");

	}
	pr_debug( "[ilnp6.c] ------------------------------------------\n");

}

/* Kernel thread that run every second to check the I-LV cache
 * and delete expired entries
 * ry6 - standard have changed to disallow ambiguous function declaration; use void as when called, there exists no data to be passed on. TODO: check
 */
int check_cache(void *data)
{
  pr_debug("[ilnp6.c] check_cache():");
    unsigned long cur_time;
    struct ilnp_addr_cache *element, *next;

    while (!kthread_should_stop()) {
	cur_time = jiffies;
	set_current_state(TASK_RUNNING);

	/*Check ILNP address cache*/
	//spin_lock(&addr_cache_lock);
	list_for_each_entry_safe(element, next, &addr_cache->list, list) {
	   /* ILNP is disabled, clear all cache*/
	   if (disable_ilnp == 1) {
	   	pr_debug( "[ilnp6.c] check_cache(): ILNP is disabled, delete all entry\n");
	      	list_del(&element->list);
	      	kmem_cache_free(addr_cache_kmem, element);
	      	print_addr_cache();
	   }

	   else if ((cur_time/HZ - element->entry->timestamp/HZ) > CACHE_TIME_OUT) {
	      	pr_debug( "[ilnp6.c] check_cache(): Entry %x expired\n", htonl(element->entry->nid) );
	      	list_del(&element->list);
	      	kmem_cache_free(addr_cache_kmem, element);
		print_addr_cache();

	   }
	}
	//spin_unlock(&addr_cache_lock);


	set_current_state(TASK_INTERRUPTIBLE);
	ssleep(1);

    }

    return 0;
}

/* Receive I-LV from userspace via netlink socket
 * when getaddrinfo() is called
 */
static void nl_data_ready (struct sk_buff *skb)
{

	struct nlmsghdr *nlh = NULL;
	struct ilnp_cache_entry *tmp;
	if(skb == NULL) {
	    pr_debug("[ilnp6.c] nl_data_ready(): ilnp6 - skb is NULL \n");
	    return ;
	}
	nlh = (struct nlmsghdr *)skb->data;
	tmp = (struct ilnp_cache_entry *) NLMSG_DATA(nlh);
	pr_debug( "[ilnp6.c] nl_data_ready(): received netlink message payload: \n");

	if (disable_ilnp == 1) {
		pr_debug( "[ilnp6.c] nl_data_ready(): ILNP is disabled, ignore message\n");
	}

	else {
		pr_debug( "[ilnp6.c] nl_data_ready(): L64: %x, NID: %x\n", htonl(tmp->l64), htonl(tmp->nid) );

		ilnp6_add_addr(tmp);
	}


}

/* A timer task that will be called when a specified L64 is expired */
void ilcc_expired(unsigned long data)
{

    struct l64_info *l64_entry = (struct l64_info *)data;

    pr_debug( "[ilnp6.c] ilcc_expired(): Locator %x expired", htonl(l64_entry->l64));
    l64_entry->flag = L64_EXPIRED;
    print_ilcc();

}

/* A timer task that will be called when a session is timed out */
void ilnp6_session_timeout(unsigned long data)
{

    struct ilcc_table *ilcc_entry = (struct ilcc_table *)data;

    pr_debug( "[ilnp6.c] ilnp6_session_timeout(): ILNP6 session with %x expired, reset nonce value\n", htonl(ilcc_entry->ilcc_info->nid));
    ilcc_entry->ilcc_info->nonce_cn = 0;
    ilcc_entry->ilcc_info->nonce_local = 0;
    print_ilcc();

}

/* Add a new entry to ILCC based on the provided information */
int add_ilcc(uint64_t l64, uint64_t nid, uint32_t prec, uint32_t lifetime, char *ifname)
{
	struct ilcc_table *tmp_entry, *entry;
	struct l64_info *tmp_l64_entry;
	int i;
  pr_debug("[ilnp6.c] add_ilcc(): \n");
	// Never Add itself to ILCC (e.g. from loopback packets)
	//spin_lock(&ilcc_lock);
	hash_for_each(ilcc_info_table, i, entry, hlist) {
		if (entry->ilcc_info->nid_local == nid) {
			pr_debug( "[ilnp6.c] add_ilcc(): Do not add itself to ILCC\n");
			//spin_unlock(&ilcc_lock);
			return 1;

		}

	}
	//spin_unlock(&ilcc_lock);

	pr_debug( "[ilnp6.c] add_ilcc(): Not in ILCC; add entry\n");


	tmp_entry = kmem_cache_zalloc(ilcc_kmem, GFP_ATOMIC);
	tmp_entry->ilcc_info = kmalloc(sizeof(struct ilnp_ilcc), GFP_ATOMIC);
	tmp_entry->ilcc_info->nid = nid;
	memcpy(tmp_entry->ilcc_info->ifname, ifname, IFNAMSIZ);
	/*nonce value -> set to 0 at start*/
	tmp_entry->ilcc_info->nonce_local = 0;
	tmp_entry->ilcc_info->nonce_cn = 0;
	setup_timer(&tmp_entry->ilcc_info->session_timer, ilnp6_session_timeout, (unsigned long)tmp_entry);
	mod_timer(&tmp_entry->ilcc_info->session_timer, jiffies + ILNP_SESSION_TIMEOUT*HZ);

	/*locator*/
	tmp_entry->ilcc_info->l64_info = kmem_cache_zalloc(l64_kmem, GFP_ATOMIC);
	INIT_LIST_HEAD(&tmp_entry->ilcc_info->l64_info->list);
	tmp_l64_entry = kmem_cache_zalloc(l64_kmem, GFP_ATOMIC);
	tmp_l64_entry->l64 = l64;
	tmp_l64_entry->prec = prec;
	tmp_l64_entry->flag = L64_ACTIVE;
// 	    tmp_l64_entry->timestamp = jiffies;
	tmp_l64_entry->lifetime = lifetime;
	setup_timer(&tmp_l64_entry->timer, ilcc_expired, (unsigned long)tmp_l64_entry);
	mod_timer(&tmp_l64_entry->timer, jiffies + lifetime*HZ);

	tmp_entry->ilcc_info->l64_local = kmem_cache_zalloc(l64_kmem, GFP_ATOMIC);

	//spin_lock(&ilcc_lock);
	INIT_LIST_HEAD(&tmp_entry->ilcc_info->l64_local->list);

	list_add_tail(&tmp_l64_entry->list, &tmp_entry->ilcc_info->l64_info->list);
	//list_add_tail(&tmp_entry->list, &ilcc->list);
	hash_add(ilcc_info_table, &tmp_entry->hlist, nid);

	print_ilcc();
	//spin_unlock(&ilcc_lock);

	return 0;
}

/* Check wether the provided IPv6 address is in ILCC or not - author: ry6 */
int in_ilcc(struct in6_addr *address)
{
	uint64_t l64, nid;
	struct ilcc_table *ilcc_element;
	int in_ilcc;
	int i;

	pr_debug("[ilnp6.c] in_ilcc(): start\n");

	in_ilcc = 0;

	memcpy(&l64, &address-> s6_addr[0], sizeof(address->s6_addr[0])*8);
	memcpy(&nid, &address-> s6_addr[8], sizeof(address->s6_addr[0])*8);

	hash_for_each(ilcc_info_table, i, ilcc_element, hlist) {
		if (nid == ilcc_element->ilcc_info->nid) {
			struct l64_info *l64_entry;
			pr_debug( "[ilnp6.c] in_ilcc(): nid found in ilcc");
			list_for_each_entry(l64_entry, &ilcc_element->ilcc_info->l64_info->list,list) {
				if(l64==l64_entry->l64){
					in_ilcc = 1;
					pr_debug( "[ilnp6.c] in_ilcc(): l64 found in ILCC\n");
					break;
				}
			}
			break;
		}
	}
	return in_ilcc;
}

/* Check whether the provided IPv6 address is an ILNP host or not (in ILCC)*/
int is_ilnp6(struct in6_addr *address)
{
	uint64_t l64, nid;
	struct ilnp_addr_cache *element;
	struct ilcc_table *ilcc_element;
	int in_ilcc, in_cache;

	if (cur_dev == NULL) {
		cur_dev = first_net_device(&init_net);
	}

	in_ilcc = 0;
	in_cache = 0;

	memmove(&l64, &address->s6_addr[0], sizeof(address->s6_addr[0])*8);
	memmove(&nid, &address->s6_addr[8], sizeof(address->s6_addr[0])*8);

	pr_debug( "[ilnp6.c] is_ilnp6(): Check if destination is ILNP (NID: %x, L64: %x)\n", htonl(nid), htonl(l64));
	print_addr_cache();

	//spin_lock(&addr_cache_lock);
	list_for_each_entry(element, &addr_cache->list, list) {
		if (l64 == element->entry->l64 &&
			nid == element->entry->nid) {
				pr_debug( "[ilnp6.c] is_ilnp6(): in cache\n");
				in_cache = 1;
				/*Add to ILCC*/
				//spin_lock(&ilcc_lock);
				hash_for_each_possible(ilcc_info_table, ilcc_element, hlist, nid) {
					if (nid == ilcc_element->ilcc_info->nid) {
						in_ilcc = 1;
						pr_debug( "[ilnp6.c] is_ilnp6(): in ILCC\n");
						break;

					}
				}
				//spin_unlock(&ilcc_lock);
				if(!in_ilcc) {
					pr_debug( "[ilnp6.c] is_ilnp6(): in_ilcc=0 Initial interface: %s\n", cur_dev->name);
					if (cur_dev == NULL) {
						pr_debug( "[ilnp6.c] is_ilnp6(): in_ilcc=0 cur_dev == NULL - Unknown active interface, cannot add entry to ILCC\n");

					}
					else {
						//put loopback interface to ILCC first
						add_ilcc(l64,nid,element->entry->l64_prec,L64_DEFAULT_LIFETIME,"lo");
					}

					break;
				}


			}
		}
		//spin_unlock(&addr_cache_lock);

		pr_debug("[ilnp6.c] is_ilnp6() = %i \n",in_cache);
		return in_cache;

}


/* Called when the host send ping request, ping reply including UDP
 * to check if the host itself and/or CN has already moved.
 * The source/destination L64 will be changed accordingly.
 * NOTE we do not need this code anymore, we modify how checksum works instead
 */
// int ilnp6_node_move(struct in6_addr *saddr, struct in6_addr *daddr)
// {
//
//   	uint64_t l64, nid, l64_local, nid_local;
// 	struct ilcc_table *ilcc_element;
// 	struct l64_info *l64_entry;
//
// 	memcpy(&l64, &daddr->s6_addr[0], sizeof(daddr->s6_addr[0])*8);
// 	memcpy(&nid, &daddr->s6_addr[8], sizeof(daddr->s6_addr[0])*8);
//
// 	memcpy(&l64_local, &saddr->s6_addr[0], sizeof(saddr->s6_addr[0])*8);
// 	memcpy(&nid_local, &saddr->s6_addr[8], sizeof(saddr->s6_addr[0])*8);
//
// 	pr_debug( "[ilnp6.c] Check if saddr/daddr has moved -- src_l64: %x src_nid: %x, dst_l64: %x dst_nid: %x)\n",
// 	       htonl(l64_local), htonl(nid_local), htonl(l64), htonl(nid));
//
// 	spin_lock(&ilcc_lock);
//   	hash_for_each_possible(ilcc_info_table, ilcc_element, hlist, nid) {
// 	    if (nid == ilcc_element->ilcc_info->nid) {
//
// 		/*Check if destination's L64 is changed (the CN moved)*/
// 		list_for_each_entry(l64_entry, &ilcc_element->ilcc_info->l64_info->list, list) {
// 		    if (l64_entry->flag == L64_ACTIVE && l64 != l64_entry->l64) {
// 			/* Valid L64 in cache, but different from the one got from getaddrinfo() -> rewrite L64*/
// 			memcpy(&daddr->s6_addr[0], &l64_entry->l64, sizeof(daddr->s6_addr[0])*8);
// 			pr_debug( "[ilnp6.c] CN has changed location from: %x to %x\n", htonl(l64), htonl(l64_entry->l64));
// 			break;
// 		    }
// 		}
//
// 		/*Check if sender's L64 is changed (the node moved)*/
// 		if (l64_local == 0 && nid_local == 0) {
// 			/* no information of src address provided, let the kernel choose
// 			 * address first. Then, we can re-write it when ilnp_send() is called.
// 			 */
// 		}
// 		else {
// 			list_for_each_entry(l64_entry, &ilcc_element->ilcc_info->l64_local->list, list) {
// 				if (l64_entry->flag == L64_ACTIVE && l64_local != l64_entry->l64) {
// 					/* Valid L64 in cache, but different from the one got from getaddrinfo() -> rewrite L64*/
// 					memcpy(&saddr->s6_addr[0], &l64_entry->l64, sizeof(saddr->s6_addr[0])*8);
// 					pr_debug( "[ilnp6.c] I have changed location from: %x to %x\n", htonl(l64_local), htonl(l64_entry->l64));
// 					break;
// 				}
// 			}
// 		}
//  	    }
//  	}
// 	spin_unlock(&ilcc_lock);
//
// 	/* Check if outgoing interface is changed*/
// // 	if (strncmp(cur_dev->name, "lo", IFNAMSIZ) != 0 && cur_dev->ifindex != *outif) {
// // 		pr_debug( "[ilnp6.c] Out going interface change from: %d to %d\n", *outif, cur_dev->ifindex);
// // 		*outif = cur_dev->ifindex;
// // 	}
//
// 	return 0;
//
// }


/* Called when receiving a nonce option from ILNP packet
 */
int ilnp6_check_nonce(struct sk_buff *skb)
{

	struct ilnp6_nonceopt *nonceopt;
	struct ipv6hdr *hdr = ipv6_hdr(skb);
	struct ilcc_table *ilcc_element;
	uint64_t nid;

	memcpy(&nid, &hdr->saddr.s6_addr[8], sizeof(hdr->saddr.s6_addr[0])*8);
	nonceopt = (struct ilnp6_nonceopt *)(skb_network_header(skb) + skb_network_header_len(skb) + 2);

	//spin_lock(&ilcc_lock);
	hash_for_each_possible(ilcc_info_table, ilcc_element, hlist, nid) {
	    if (nid == ilcc_element->ilcc_info->nid) {

		pr_debug( "[ilnp6.c] ilnp6_check_nonce(): Sender in ILCC\n");
		/* Check if remote nonce is in ILCC, if not add it*/
		if (ilcc_element->ilcc_info->nonce_cn == 0) {
		    pr_debug( "[ilnp6.c] ilnp6_check_nonce(): Add remote nonce to ILCC, value: %d \n", nonceopt->nonce);
		    ilcc_element->ilcc_info->nonce_cn = nonceopt->nonce;
		}

		/* Received nonce value is different from the one in ILCC*/
		else if (ilcc_element->ilcc_info->nonce_cn != nonceopt->nonce) {
		    pr_debug( "[ilnp6.c] ilnp6_check_nonce(): Invalid nonce value (recv: %d should be: %d), drop packet \n",
		      nonceopt->nonce, ilcc_element->ilcc_info->nonce_cn);
		    //spin_unlock(&ilcc_lock);
		    return 1;

		}

		/* Check if local nonce is present, if not add it
		 * NOTE we use the same nonce for both direction
		 * by now. This is more suitable for conectionless
		 * protocols such as UDP and ICMP (ping). In the
		 * future, different nonce value may be used for
		 * conection-oriented protocols. Please refer to
		 * RFC 6740, section 2.3.
		 */
		if (ilcc_element->ilcc_info->nonce_local == 0) {
		    pr_debug( "[ilnp6.c] ilnp6_check_nonce(): Add remote nonce to ILCC, value: %d \n", nonceopt->nonce);
		    ilcc_element->ilcc_info->nonce_local = nonceopt->nonce;
		}

	    }
	}
	//spin_unlock(&ilcc_lock);
	return 0;
}

/* Called when the kernel detect that it receive an ILNPv6 packet
 */
int ilnp6_rcv(struct sk_buff *skb)
{

  	uint64_t l64, nid, l64_local, nid_local;
	struct ilcc_table *ilcc_element;
	struct l64_info *l64_entry, *tmp_l64_entry;
	int in_ilcc, exist_l64, have_active_l64;

	struct ipv6hdr *hdr = ipv6_hdr(skb);
	struct net_device *dev = skb->dev;

	in_ilcc = 0;
	exist_l64 = 0;
	//have_active_l64 = 0;

	memcpy(&l64, &hdr->saddr.s6_addr[0], sizeof(hdr->saddr.s6_addr[0])*8);
	memcpy(&nid, &hdr->saddr.s6_addr[8], sizeof(hdr->saddr.s6_addr[0])*8);
	memcpy(&l64_local, &hdr->daddr.s6_addr[0], sizeof(hdr->daddr.s6_addr[0])*8);
	memcpy(&nid_local, &hdr->daddr.s6_addr[8], sizeof(hdr->daddr.s6_addr[0])*8);


	//spin_lock(&ilcc_lock);
	hash_for_each_possible(ilcc_info_table, ilcc_element, hlist, nid) {
	    if (nid == ilcc_element->ilcc_info->nid) {
		in_ilcc = 1;
		pr_debug( "[ilnp6.c] ilnp6_rcv(): Sender in ILCC\n");

		/* Update timestamp of the session*/
		mod_timer(&ilcc_element->ilcc_info->session_timer, jiffies + ILNP_SESSION_TIMEOUT*HZ);

		/*Check if information of net_device exist; if not, add it*/
		if (strncmp(ilcc_element->ilcc_info->ifname, "lo", IFNAMSIZ) == 0) {
		    pr_debug( "[ilnp6.c] ilnp6_rcv(): Fill in device information\n");
		    memcpy(ilcc_element->ilcc_info->ifname, dev->name, IFNAMSIZ);

		}


		/*Check if local nid/l64 is in the cache*/
		if (ilcc_element->ilcc_info->nid_local == nid_local) {
		      	pr_debug( "[ilnp6.c] ilnp6_rcv(): Have info of local I-L_V\n");
			//check if destination L64 is still active or valid
			list_for_each_entry(l64_entry, &ilcc_element->ilcc_info->l64_local->list, list) {
				if (l64_entry->l64 == l64_local) {
					if (l64_entry->flag == L64_VALID || l64_entry->flag == L64_ACTIVE) {
						/*Valid L64 accept packet, do nothing*/
						pr_debug( "[ilnp6.c] ilnp6_rcv(): valid L64: %x, accept packet\n", htonl(l64_entry->l64));

					}
					/*Expired L64, maybe delayed packet from previous location*/
					else if (l64_entry->flag == L64_EXPIRED || l64_entry->flag == L64_AGED) {
						pr_debug( "[ilnp6.c] ilnp6_rcv(): Expired L64 received, may from delayed packet (drop)\n");
						//spin_unlock(&ilcc_lock);
						goto error;
					}
					/*Invalid flag, should not happen*/
					else {
						pr_debug( "[ilnp6.c] ilnp6_rcv(): Invalid flag in ILCC (drop)\n");
						//spin_unlock(&ilcc_lock);
						goto error;
					}

				}
			}
		}
		else {
		      pr_debug( "[ilnp6.c] ilnp6_rcv(): Add info of local I-L_V\n");
		      ilcc_element->ilcc_info->nid_local = nid_local;
		      tmp_l64_entry = kmem_cache_zalloc(l64_kmem, GFP_ATOMIC);
		      tmp_l64_entry->l64 = l64_local;
		      tmp_l64_entry->prec = L64_DEFAULT_PREC;
		      tmp_l64_entry->flag = L64_ACTIVE;
// 		      tmp_l64_entry->timestamp = jiffies;
 		      tmp_l64_entry->lifetime = L64_DEFAULT_LIFETIME;

		      setup_timer(&tmp_l64_entry->timer, ilcc_expired, (unsigned long)tmp_l64_entry);
		      mod_timer(&tmp_l64_entry->timer, jiffies + L64_DEFAULT_LIFETIME*HZ);

		      list_add_tail(&tmp_l64_entry->list, &ilcc_element->ilcc_info->l64_local->list);


		}

		/*Check if sender's L64 is valid*/
		list_for_each_entry(l64_entry, &ilcc_element->ilcc_info->l64_info->list, list) {
		    if (l64_entry->l64 == l64) {
			exist_l64 = 1;
			if (l64_entry->flag == L64_VALID || l64_entry->flag == L64_ACTIVE) {
			    /*Valid L64 -> update timestamp*/
			    pr_debug( "[ilnp6.c] ilnp6_rcv(): Update timestamp of remote L64: %x\n", htonl(l64_entry->l64));
			    //have_active_l64 = 1;
			    mod_timer(&l64_entry->timer, jiffies + l64_entry->lifetime*HZ);
			    //spin_unlock(&ilcc_lock);
			    goto ok;
			}
			/*Expired L64, maybe delayed packet from previous location
			  */
			else if (l64_entry->flag == L64_EXPIRED) {
//			    if (have_active_l64) {
				pr_debug( "[ilnp6.c] ilnp6_rcv(): Expired L64 received, accept packet since NID and nonce is correct\n");
				/* change flag to ACTIVE and update timestamp as well!
				   In case of server that only listening */
				l64_entry->flag = L64_ACTIVE;
				mod_timer(&l64_entry->timer, jiffies + l64_entry->lifetime*HZ);
				//spin_unlock(&ilcc_lock);
			    	goto ok;

			}
			/*Invalid flag, should not happen*/
			else {
				pr_debug( "[ilnp6.c] ilnp6_rcv(): Invalid L64 flag received, drop\n");
				//spin_unlock(&ilcc_lock);
			    	goto error;
			}

		    }

		}
		/*Incorrect L64, maybe from spoofing*/
		if (!exist_l64) {
		    pr_debug( "[ilnp6.c] Invalid L64\n");
		    //spin_unlock(&ilcc_lock);
		    goto error;
		}

	    }
	    /* Receive packet from itself e.g. loopback*/
	    else if (nid == ilcc_element->ilcc_info->nid_local) {
	      	in_ilcc = 1;
		pr_debug( "[ilnp6.c] ilnp6_rcv(): Own address, do not add to ILCC\n");

	    }
	}
	print_ilcc();
	//spin_unlock(&ilcc_lock);


	if(!in_ilcc) {
	    add_ilcc(l64,nid,1000,L64_DEFAULT_LIFETIME,dev->name);
	    /*Add info of local NID and L64 -- we cheat here*/
	    ilnp6_rcv(skb);
	}
ok:
	return 0;

error:
	return 1;
}

/* Called when the kernel detect that it abouts to send ILNPv6 packet
 */
int ilnp6_send(struct sk_buff *skb, struct in6_addr *saddr, struct in6_addr *daddr, unsigned char proto)
{
	/*Check ILCC (but it should have the entry since connect() was called*/
	uint64_t l64, nid, l64_local, nid_local, active_l64;
	struct ilcc_table *element;
	struct l64_info *l64_element, *tmp_l64_entry;
	int in_ilcc, exist_local_l64, has_other_active, node_move, cn_move;
	struct ipv6_destopt_hdr *dstopt;
	struct ilnp6_nonceopt  *nonceopt;
	uint32_t nonce;

	in_ilcc = 0;
	exist_local_l64 = 0;
	has_other_active = 0;
	node_move = 0;
	cn_move = 0;

	memcpy(&l64, &daddr->s6_addr[0], sizeof(daddr->s6_addr[0])*8);
	memcpy(&nid, &daddr->s6_addr[8], sizeof(daddr->s6_addr[0])*8);
	memcpy(&l64_local, &saddr->s6_addr[0], sizeof(saddr->s6_addr[0])*8);
	memcpy(&nid_local, &saddr->s6_addr[8], sizeof(saddr->s6_addr[0])*8);


	//spin_lock(&ilcc_lock);
	hash_for_each_possible(ilcc_info_table, element, hlist, nid) {
	   if (nid == element->ilcc_info->nid) {
		in_ilcc = 1;
		pr_debug( "[ilnp6.c] ilnp6_send(): Destination in ILCC\n");

		/* Update timestamp of the session */
		mod_timer(&element->ilcc_info->session_timer, jiffies + ILNP_SESSION_TIMEOUT*HZ);

		/* Add information of local nid and l64 */
		if (element->ilcc_info->nid_local != nid_local)
		      element->ilcc_info->nid_local = nid_local;

		/* Check local L64
		 * If there is no other active interface than the one
		 * specified in the header, we treat that L64 as the
		 * current active L64. If there is another active
		 * L64, and the current prefix is not ACTIVE, it means
		 * that the node has already moved, then we must use
		 * the new L64 instead.
		 */
		list_for_each_entry(l64_element, &element->ilcc_info->l64_local->list, list) {
		    if (l64_local != l64_element->l64 && l64_element->flag == L64_ACTIVE) {
			has_other_active = 1;
			pr_debug( "[ilnp6.c] ilnp6_send(): Has another active interface\n");
			active_l64 = l64_element->l64;

		    }

		}

		list_for_each_entry(l64_element, &element->ilcc_info->l64_local->list, list) {
		    if (l64_local == l64_element->l64) {
			exist_local_l64 = 1;
			pr_debug( "[ilnp6.c] ilnp6_send(): Local L64 in cache\n");
			if (l64_element->flag != L64_ACTIVE && !has_other_active) {
			    pr_debug( "[ilnp6.c] ilnp6_send(): Set flag to ACTIVE\n");
			    l64_element->flag = L64_ACTIVE;
			    mod_timer(&l64_element->timer, jiffies + l64_element->lifetime*HZ);
			}
			else if (l64_element->flag == L64_ACTIVE) {
			    pr_debug( "[ilnp6.c] ilnp6_send(): The provided source L64 is still active, use this one\n");
			    has_other_active = 0;
			}
			break;
		    }

		}

		if (has_other_active) {
		    pr_debug( "[ilnp6.c] ilnp6_send(): My location already changed, update source L64 in the header\n");
		    memcpy(&saddr->s6_addr[0], &active_l64, sizeof(saddr->s6_addr[0])*8);
		    node_move = 1;
		}

		if (!exist_local_l64) {

		    pr_debug( "[ilnp6.c] ilnp6_send(): Add local L64 to cache\n");
		    tmp_l64_entry = kmem_cache_zalloc(l64_kmem, GFP_ATOMIC);
		    tmp_l64_entry->l64 = l64_local;
		    tmp_l64_entry->prec = L64_DEFAULT_PREC;
		    tmp_l64_entry->flag = L64_ACTIVE;
		    tmp_l64_entry->lifetime = L64_DEFAULT_LIFETIME;
		    //tmp_l64_entry->lu_sent = 0;
		    //tmp_l64_entry->wait_for_ack = 0;
		    setup_timer(&tmp_l64_entry->timer, ilcc_expired, (unsigned long)tmp_l64_entry);
		    mod_timer(&tmp_l64_entry->timer, jiffies + L64_DEFAULT_LIFETIME*HZ);

		    list_add_tail(&tmp_l64_entry->list, &element->ilcc_info->l64_local->list);

		}

		/* Generate local nonce (if not present)*/
		if (element->ilcc_info->nonce_local == 0) {
		     get_random_bytes(&nonce, sizeof(nonce));
		     element->ilcc_info->nonce_local = nonce;
		     pr_debug( "[ilnp6.c] ilnp6_send(): Generate local nonce: %d\n", nonce);
		}

		/* put nonce option */
		skb_push(skb, sizeof(*nonceopt));
		nonceopt = (struct ilnp6_nonceopt*) skb->data;
		nonceopt->type = ILNP6_TLV_NONCE;
		nonceopt->length = ILNP_NONCE_32; // for 32-bit
		nonceopt->nonce = element->ilcc_info->nonce_local;

		skb_push(skb, sizeof(*dstopt));
		dstopt = (struct ipv6_destopt_hdr*) skb->data;
		dstopt->nexthdr =  proto;
		dstopt->hdrlen = 0;


		/* Check destination L64*/
		list_for_each_entry(l64_element, &element->ilcc_info->l64_info->list, list) {
		    if (l64_element->flag == L64_ACTIVE && l64 != l64_element->l64) {
			/* Valid L64 in cache, but different from the one got from getaddrinfo() -> rewrite L64*/
			memcpy(&daddr->s6_addr[0], &l64_element->l64, sizeof(daddr->s6_addr[0])*8);
			pr_debug( "[ilnp6.c] ilnp6_send(): CN already changed location; update L64 in header, %x\n", htonl(l64_element->l64));
			cn_move = 1;

		    }

		}

		if (cn_move == 0) {
			list_for_each_entry(l64_element, &element->ilcc_info->l64_info->list, list) {
				if (l64 == l64_element->l64 && l64_element->flag != L64_ACTIVE) {
					/* CN has not moved, the provided L64 is ACTIVE */
					l64_element->flag = L64_ACTIVE;
					pr_debug( "[ilnp6.c] ilnp6_send(): Provided L64 is ACTIVE\n");

				}

			}
		}

	   }

	}
	print_ilcc();
	//spin_unlock(&ilcc_lock);


	if(!in_ilcc) {
	    pr_debug( "[ilnp6.c] ilnp6_send(): Destination not in ILCC\n");
	    pr_debug( "[ilnp6.c] Current interface: %s\n", skb->dev->name);
	    if (skb->dev == NULL) {
		    pr_debug( "[ilnp6.c] Unknown active interface, cannot add entry to ILCC\n");

	    }
	    else {
		 pr_debug( "[ilnp6.c] ilnp6_send(): Add destination to ILCC\n");
		 add_ilcc(l64,nid,30,L64_DEFAULT_LIFETIME, skb->dev->name);
	    }
	}


	return node_move;

}

int send_lu(uint64_t l64, struct net_device *dev, struct in6_addr *dst, struct in6_addr *src, int is_ack, uint32_t nonce)
{
	int hdr_len, data_len;
	struct sk_buff *skb;
	struct lu_data *data;
	struct icmp6hdr *icmph;
	struct ipv6hdr *ip6h;
	struct ipv6_destopt_hdr *dstopt;
	struct ilnp6_nonceopt  *nonceopt;
	uint64_t src_l64, dst_l64;

	hdr_len = sizeof(*icmph) + sizeof(*ip6h) + sizeof(*dstopt) + sizeof(*nonceopt) + ETH_HLEN;
	data_len = sizeof(struct lu_data);

	skb = alloc_skb(hdr_len + data_len, GFP_ATOMIC);
	if (!skb) {
		pr_debug( "[ilnp6.c] send_lu(): Error allocate\n");
		return 1;
	}

	skb_reserve(skb, hdr_len);

	data = (struct lu_data *) skb_put(skb, data_len);
	data->l64 = l64;
	data->prec = htons(L64_DEFAULT_PREC);
	data->lifetime = htons(L64_DEFAULT_LIFETIME);

	/* ICMPv6 Header*/
	skb_push(skb, sizeof(*icmph));
	skb_reset_transport_header(skb);
	icmph = icmp6_hdr(skb);
	icmph->icmp6_type = ILNP6_LOCATOR_UPDATE;
	if (is_ack)
		icmph->icmp6_code = 2; //LU-ACK
	else icmph->icmp6_code = 1; //LU
	icmph->icmp6_cksum = 0;
	icmph->icmp6_dataun.un_data8[0] = 1; //number of locator
	icmph->icmp6_dataun.un_data8[1] = 0; //reserved
	icmph->icmp6_dataun.un_data8[2] = 0; //reserved
	icmph->icmp6_dataun.un_data8[3] = 0; //reserved

	// Backup L64 value
	memcpy(&src_l64, &src->s6_addr[0], sizeof(src->s6_addr[0])*8);
	memcpy(&dst_l64, &dst->s6_addr[0], sizeof(dst->s6_addr[0])*8);

	// Remove L64 from saddr and daddr, so only NID will be used for checksum calculation
	memset(&dst->s6_addr[0], 0, sizeof(dst->s6_addr[0])*8);
	memset(&src->s6_addr[0], 0, sizeof(src->s6_addr[0])*8);

	icmph->icmp6_cksum = csum_ipv6_magic(src, dst,
					sizeof(struct icmp6hdr) + data_len, IPPROTO_ICMPV6,
					csum_partial(icmph, sizeof(struct icmp6hdr) + data_len, 0));

	if (icmph->icmp6_cksum == 0)
		icmph->icmp6_cksum = 0xffff;

	// Put L64 back to saddr and daddr
	memcpy(&dst->s6_addr[0], &dst_l64, sizeof(dst->s6_addr[0])*8);
	memcpy(&src->s6_addr[0], &src_l64, sizeof(src->s6_addr[0])*8);

	/* Nonce option */
	skb_push(skb, sizeof(*nonceopt));
	nonceopt = (struct ilnp6_nonceopt*) skb->data;
	nonceopt->type = ILNP6_TLV_NONCE;
	nonceopt->length = ILNP_NONCE_32; // for 32-bit
	nonceopt->nonce = nonce; // tested nonce value

	skb_push(skb, sizeof(*dstopt));
	dstopt = (struct ipv6_destopt_hdr*) skb->data;
	dstopt->nexthdr =  IPPROTO_ICMPV6; //icmpv6
	dstopt->hdrlen = 0;

	/* IPv6 Header */
	skb_push(skb, sizeof(*ip6h));
	skb_reset_network_header(skb);
	ip6h = ipv6_hdr(skb);

	ip6h->version = 6;
	ip6h->priority = 0;
	memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
	//ip6h->flow_lbl[0] = 0x08;
	ip6h->payload_len = htons(sizeof(struct icmp6hdr) + sizeof(struct ipv6_destopt_hdr) + sizeof(struct ilnp6_nonceopt) + data_len);
	ip6h->hop_limit      = 64;
	ip6h->nexthdr = IPPROTO_DSTOPTS; // destination option (for nonce)
	memcpy(&ip6h->saddr, src, sizeof(struct in6_addr));
	memcpy(&ip6h->daddr, dst, sizeof(struct in6_addr));


	/*Send LU*/
	icmpv6_send_lu(skb, dev, dst, src);

	pr_debug( "[ilnp6.c] send_lu(): Successfully send LU\n");

	return 0;

}

/* A timer task to perform LU retransmission.
 * It is called when retransmission timed out
 */
void ilnp6_ret(unsigned long data)
{
    struct lu_table *lu_entry = (struct lu_table *)data;

    int i;
    struct ilcc_table *entry;
    struct l64_info *l64_entry, *tmp_l64_entry;

   //spin_lock(&lu_table_lock);

    // We set the flag of new L64 in ILCC to ACTIVE before send the first LU
    if (lu_entry->lu_info->counter == 1) {
	pr_debug( "[ilnp6.c] ilnp6_ret(): Prepare to send the first LU\n");
	pr_debug( "[ilnp6.c] ilnp6_ret(): HANDOFF START: %d\n", jiffies_to_msecs(jiffies));
	//spin_lock(&ilcc_lock);
	hash_for_each(ilcc_info_table, i, entry, hlist) {
		list_for_each_entry(l64_entry, &entry->ilcc_info->l64_local->list, list) {
			/*Check if new L64 already in ILCC*/
			if (l64_entry->l64 == lu_entry->lu_info->l64) {
				pr_debug( "[ilnp6.c] ilnp6_ret(): Mark prefix %x as ACTIVE before sending LU\n", htonl(l64_entry->l64));
				l64_entry->flag = L64_ACTIVE;
			}
			else {

				if (l64_entry->flag == L64_EXPIRED || l64_entry->flag == L64_AGED ){
					pr_debug( "[ilnp6.c] ilnp6_ret(): %x is either expired or aged; do not change flag and skip. continue; \n",htonl(l64_entry->l64));
					continue;
				}

				if (handoff_mode == 0) {
					pr_debug( "[ilnp6.c] ilnp6_ret(): Soft handoff: Mark previously active prefix %x  as VALID\n", htonl(l64_entry->l64));
					l64_entry->flag = L64_VALID;

				}
				else if (handoff_mode == 1) {
					pr_debug( "[ilnp6.c] ilnp6_ret(): Hard handoff: Mark previously active prefix %x  as AGED\n", htonl(l64_entry->l64));
					l64_entry->flag = L64_AGED;
				}
				else {
					pr_debug( "[ilnp6.c] ilnp6_ret(): Invalid handoff mode, use soft handoff: Mark previously active prefix %x  as VALID\n", htonl(l64_entry->l64));
					l64_entry->flag = L64_VALID;
				}

			}
		}

	}
	//spin_unlock(&ilcc_lock);
    }

    if (lu_entry->lu_info->counter <= 6) {
	struct net_device *dev;
	dev = dev_get_by_name(&init_net, lu_entry->lu_info->ifname);
	pr_debug( "[ilnp6.c] ilnp6_ret(): Send LU#%d via %s\n", lu_entry->lu_info->counter, dev->name);
	send_lu(lu_entry->lu_info->l64, dev, &lu_entry->lu_info->daddr, &lu_entry->lu_info->saddr, 0, lu_entry->lu_info->nonce);
	lu_entry->lu_info->counter++;
	mod_timer(&lu_entry->lu_info->timer, jiffies + msecs_to_jiffies(1000)); // retransmit every second
    }
    else {
	pr_debug( "[ilnp6.c] ilnp6_ret(): Counter exceed, handoff failed!\n");
	cur_dev = new_dev;
	kfree(lu_entry->lu_info);
	hash_del(&lu_entry->hlist);
	kmem_cache_free(lu_cache_kmem, lu_entry);

    }
    //spin_unlock(&lu_table_lock);

}

/* Called when the node received an LU message*/
int rcv_lu(struct sk_buff *skb)
{
      struct lu_msg *msg;
      struct ipv6hdr *ip6h = ipv6_hdr(skb);
      uint64_t src_nid;
      struct ilcc_table *ilcc_element;
      struct lu_table *lu_entry;
      struct l64_info *l64_entry, *tmp_l64_entry;
      int in_ilcc, exist_l64;
      struct in6_addr *src, *dst;
      struct hlist_node *tmp;
      uint32_t my_nonce;

      src = kmalloc(sizeof(struct in6_addr), GFP_ATOMIC);
      dst = kmalloc(sizeof(struct in6_addr), GFP_ATOMIC);
      pr_debug("[ilnp6.c] rcv_lu(): -- start -- \n");
       /* Check if the packet has nonce option */
       if (skb->has_nonce != 1) {
	    pr_debug( "[ilnp6.c] rcv_lu(): No nonce option in LU packet, drop\n");
	    return 1;
       }

      msg = (struct lu_msg *)skb_transport_header(skb);

      memmove(&src_nid, &ip6h->saddr.s6_addr[8], sizeof(ip6h->saddr.s6_addr[0])*8);

      /* Receive LU */
      if (msg->icmp6_code == 1) {
	  pr_debug( "[ilnp6.c] rcv_lu(): Receive LU from %s\n", skb->dev->name);
	  in_ilcc = 0;
	  exist_l64 = 0;

	  //spin_lock(&ilcc_lock);
	  hash_for_each_possible(ilcc_info_table, ilcc_element, hlist, src_nid) {
	      /*Sender's NID is in ILCC*/
	      if (src_nid == ilcc_element->ilcc_info->nid) {
		  in_ilcc = 1;
		  my_nonce = ilcc_element->ilcc_info->nonce_local;
		  pr_debug( "[ilnp6.c] rcv_lu(): Sender in ILCC\n");

		  /*Check if sender's L64 is already in ILCC*/
		  list_for_each_entry(l64_entry, &ilcc_element->ilcc_info->l64_info->list, list) {
		      if (l64_entry->l64 == msg->l64) {
			  exist_l64 = 1;
			  if (l64_entry->flag == L64_ACTIVE) {
			      /*Existing L64, maybe from duplicate LU -> update timestamp*/
			      pr_debug( "[ilnp6.c] rcv_lu(): Duplicate LU, update timestamp for L64\n");

			  }
			  /*Valid L64 but is not in used. We switch to use this L64*/
			  else if (l64_entry->flag == L64_VALID) {
			      pr_debug( "[ilnp6.c] rcv_lu(): Switch active L64\n");
			      l64_entry->flag = L64_ACTIVE;

			  }
			  /*Expired L64, maybe from previous handoff. We activate this L64 again*/
			  else if (l64_entry->flag == L64_EXPIRED) {
			      pr_debug( "[ilnp6.c] rcv_lu(): Previously expired L64 become valid\n");
			      l64_entry->flag = L64_ACTIVE;

			  }
			  /*Invalid flag in ILCC. We correct it*/
			  else {
			      pr_debug( "[ilnp6.c] rcv_lu(): Invalid flag in ILCC, correct to ACTIVE\n");
			      l64_entry->flag = L64_ACTIVE;
			  }
			  // Update lifetime
			  l64_entry->lifetime = ntohs(msg->lifetime);
			  mod_timer(&l64_entry->timer, jiffies + l64_entry->lifetime*HZ);


		      }
		      /*Another L64 in ILCC, we mark them as 'expired'*/
		      else {
			  pr_debug( "[ilnp6.c] rcv_lu(): Host change location, previous L64 becomes expired\n");
			  l64_entry->flag = L64_EXPIRED;
		      }

		  }
		  /*L64 not in ILCC. We add it*/
		  if (!exist_l64) {
		      pr_debug( "[ilnp6.c] rcv_lu(): Add new L64 to ILCC\n");
		      tmp_l64_entry = kmem_cache_zalloc(l64_kmem, GFP_ATOMIC);
		      tmp_l64_entry->l64 = msg->l64;
		      tmp_l64_entry->prec = ntohs(msg->prec);
		      tmp_l64_entry->flag = L64_ACTIVE;
		      tmp_l64_entry->lifetime = ntohs(msg->lifetime);
		      setup_timer(&tmp_l64_entry->timer, ilcc_expired, (unsigned long)tmp_l64_entry);
		      mod_timer(&tmp_l64_entry->timer, jiffies + tmp_l64_entry->lifetime*HZ);

		      list_add(&tmp_l64_entry->list, &ilcc_element->ilcc_info->l64_info->list);
		  }

	      }

	}
	print_ilcc();
	//spin_unlock(&ilcc_lock);

	 /*Sender's NID not in ILCC. We add a new entry*/
	if(!in_ilcc) {
	    pr_debug( "[ilnp6.c] rcv_lu(): Sender not in ILCC, ignore packet\n");
	    //add_ilcc(msg->l64,src_nid,ntohs(msg->prec),ntohs(msg->lifetime),skb->dev->name);
	    return 0;
	}

	/*Send LU ACK back to sender
	  All information apart from 'code' flag is the same (RFC 6743)*/

	pr_debug( "[ilnp6.c] rcv_lu(): Send LU ACK\n");
	src = &ip6h->daddr;
	memmove(&dst->s6_addr[0], &msg->l64, sizeof(dst->s6_addr[0])*8);
	memmove(&dst->s6_addr[8], &src_nid, sizeof(dst->s6_addr[0])*8);

	send_lu(msg->l64, skb->dev, dst, src, 1, my_nonce);


      }
      /* Receive LU ACK*/
      else if (msg->icmp6_code == 2) {
	  pr_debug( "[ilnp6.c] rcv_lu(): Receive LU ACK from %s from NID: %x, prefix %x\n", skb->dev->name, htonl(src_nid), htonl(msg->l64));

	  /*Upddate information of active L64 in ILCC*/
	  //spin_lock(&ilcc_lock);
	  hash_for_each_possible(ilcc_info_table, ilcc_element, hlist, src_nid) {
	      /*Sender's NID in ILCC*/
	      if (src_nid == ilcc_element->ilcc_info->nid) {

		  /*Check local L64 that receive ACK*/
		  list_for_each_entry(l64_entry, &ilcc_element->ilcc_info->l64_local->list, list) {
		      if (l64_entry->l64 == msg->l64) {


			  /*This L64 then become ACTIVE*/
			  //l64_entry->flag = L64_ACTIVE;
			  pr_debug( "[ilnp6.c] rcv_lu(): Node: %x, %x know about location change\n",
				      htonl(ilcc_element->ilcc_info->l64_info->l64), htonl(ilcc_element->ilcc_info->nid));


		      }
		       /* Currently AVTICE L64 in ILCC, we mark them as 'VALID'
			* NOTE: In fact, we've already marked this since we
			* sent the first LU. Should we remove the code?
			*/
		      else if (l64_entry->flag == L64_ACTIVE) {
			  pr_debug( "[ilnp6.c] rcv_lu(): Host change L64, the previous one become unused (but still valid) \n");
			  l64_entry->flag = L64_VALID;

		      }

		  }
		  if (skb->dev == new_dev) {
		      cur_dev = new_dev;
		      memcpy(ilcc_element->ilcc_info->ifname, new_dev->name, IFNAMSIZ);
		      pr_debug( "[ilnp6.c] rcv_lu(): Switch interface to %s\n",ilcc_element->ilcc_info->ifname);
		  }
		  else {
		      pr_debug( "[ilnp6.c] rcv_lu(): ACK received from %s, invalid interface, should be %s\n",skb->dev->name, new_dev->name);
		  }
	      }

	}
	print_ilcc();
	//spin_unlock(&ilcc_lock);

	/*We don't wait for ACK from this sender anymore*/
	/*Delete retramsmission timer and remove the LU entry from the cache */
	//spin_lock(&lu_table_lock);
	hash_for_each_possible_safe(lu_info_table, lu_entry, tmp, hlist, src_nid) {

	  if (lu_entry->lu_info->cn_nid == src_nid && lu_entry->lu_info->l64 == msg->l64) {
	      pr_debug( "[ilnp6.c] rcv_lu(): Receive ACK, cancel retransmission timer\n");
	      pr_debug( "[ilnp6.c] HANDOFF FIN: %d, %d LUs\n", jiffies_to_msecs(jiffies), lu_entry->lu_info->counter);
	      del_timer(&lu_entry->lu_info->timer);
	      kfree(lu_entry->lu_info);
	      hash_del(&lu_entry->hlist);
	      kmem_cache_free(lu_cache_kmem, lu_entry);
	      print_lu_table();
	  }
	  else {
	    pr_debug( "[ilnp6.c] rcv_lu(): Not this one, check next entry\n");

	  }

	}
	//spin_unlock(&lu_table_lock);


      }
      /*Invalid Code*/
      else {
	  pr_debug( "[ilnp6.c] rcv_lu(): Invalid LU code\n");
	  return 1;

      }

      return 0;

}

/* Called when the host receive RA from a router. If a new prefix is received,
 * it will send LU to all CNs (if any).
 */
int ilnp6_rcv_ra(struct net_device *dev, struct in6_addr *prefix, __u32 lifetime)
{
      int send, in_ilcc, i, is_active;
      struct ilcc_table *entry;
      struct l64_info *l64_entry, *tmp_l64_entry;
      struct in6_addr *src, *dst;
      struct lu_table *lu_entry;
      uint64_t new_l64;

      pr_debug( "[ilnp6.c] ilnp6_rcv_ra: Receive RA\n");

      is_active = 0;
      in_ilcc = 0;
      src = kmalloc(sizeof(struct in6_addr), GFP_ATOMIC);
      dst = kmalloc(sizeof(struct in6_addr), GFP_ATOMIC);

      memcpy(&new_l64, prefix, 8);

      /*Check if information of cur_dev exist; if not, add it*/
      if (strncmp(cur_dev->name, "lo", IFNAMSIZ) == 0) {
	  pr_debug( "[ilnp6.c] ilnp6_rcv_ra(): setup cur_dev\n");
	  cur_dev = dev;

      }

      /* Setup the home L64.
	* We assume that the first received RA is
	* the home L64
	*/
      if (l64_home == 0) {
	  l64_home = new_l64;
	  pr_debug( "[ilnp6.c] ilnp6_rcv_ra(): Setup home L64: %x\n", htonl(l64_home));
      }

      /*Send LU to all valid CNs in ILCC*/
      //spin_lock(&ilcc_lock);
      hash_for_each(ilcc_info_table, i, entry, hlist) {
	  send = 1;
	  /*put NID in LU packet*/
	  memmove(&dst->s6_addr[8], &entry->ilcc_info->nid, sizeof(dst->s6_addr[0])*8);
	  memmove(&src->s6_addr[8], &entry->ilcc_info->nid_local, sizeof(src->s6_addr[0])*8);
	  //cur_dev = dev_get_by_name(&init_net, entry->ilcc_info->ifname);
	  pr_debug( "[ilnp6.c] ilnp6_rcv_ra: Current interface: %s, Receive RA from: %s\n",cur_dev->name, dev->name);

	  /*find destination L64*/
	  list_for_each_entry(l64_entry, &entry->ilcc_info->l64_info->list, list) {
	      if (l64_entry->flag == L64_ACTIVE) {
// 		  pr_debug( "[ilnp6.c] Send LU to L64: %lld, NID: %lld",
// 			  l64_entry->l64, entry->nid);
		  is_active = 1;
		  memmove(&dst->s6_addr[0], &l64_entry->l64, sizeof(dst->s6_addr[0])*8);
		  break;
	      }
	  }

	  if (!is_active) {
	      pr_debug( "[ilnp6.c] ilnp6_rcv_ra: No current active CN, no LU to be sent\n");
	      send = 0;
	  }

	  is_active = 0;

	  /*find source L64*/
	  list_for_each_entry(l64_entry, &entry->ilcc_info->l64_local->list, list) {
	      /*Check if new L64 already in ILCC*/
	      if (l64_entry->l64 == new_l64) {
		  in_ilcc = 1;

		  if (l64_entry->flag == L64_ACTIVE || l64_entry->flag == L64_VALID || l64_entry->flag == L64_AGED) {
		      pr_debug( "[ilnp6.c] ilnp6_rcv_ra: Old prefix, no LU to be sent\n");
		      send = 0;

		  }

		  /* Previously expired L64: update timestamp and make it valid*/
		  else if (l64_entry->flag == L64_EXPIRED) {
		      pr_debug( "[ilnp6.c] ilnp6_rcv_ra: Previously expired L64 become active\n");
		      l64_entry->flag = L64_VALID;  //will become ACTIVE when send LU

		  }

		  pr_debug( "[ilnp6.c] ilnp6_rcv_ra: Update timestamp of local L64: %x\n", htonl(l64_entry->l64));
		  // Change lifetime to be the same as announced in RA
		  l64_entry->lifetime = lifetime;
		  mod_timer(&l64_entry->timer, jiffies + lifetime*HZ);

	      }
	      /*New L64 are not in ILCC, get source L64 from current active L64*/
	      else if (l64_entry->flag == L64_ACTIVE) {
// 		  pr_debug( "[ilnp6.c] From L64: %lld, NID: %lld",
// 			  l64_entry->l64, entry->nid_local);
		  is_active = 1;
		  memmove(&src->s6_addr[0], &l64_entry->l64, sizeof(src->s6_addr[0])*8);

	      }
	      /*No active interface e.g. receive new RA when there is no current active connection*/
	      if (!is_active) {
		  pr_debug( "[ilnp6.c] ilnp6_rcv_ra: No other current active interface, use new prefix as src_l64 \n");
		  memmove(&src->s6_addr[0], &new_l64, sizeof(src->s6_addr[0])*8);
	      }

	  }


	  /*send LU*/
	  if (send) {
		new_dev = dev;
		pr_debug( "[ilnp6.c] ilnp6_rcv_ra: Send LU from %s\n", cur_dev->name);

		//send_lu(new_l64, cur_dev, dst, src, 0);

		/*Add information of LU in LU table*/
		pr_debug( "[ilnp6.c] ilnp6_rcv_ra: Add information of LU in cache\n");
		//spin_lock(&lu_table_lock);
		lu_entry = kmem_cache_zalloc(lu_cache_kmem, GFP_ATOMIC);
		lu_entry->lu_info = kmalloc(sizeof(struct lu_info), GFP_ATOMIC);
		lu_entry->lu_info->cn_nid = entry->ilcc_info->nid;
		lu_entry->lu_info->nonce = entry->ilcc_info->nonce_local;
		lu_entry->lu_info->l64 = new_l64;
		memcpy(lu_entry->lu_info->ifname, cur_dev->name, IFNAMSIZ);
		memcpy(&lu_entry->lu_info->saddr, src, sizeof(struct in6_addr));
		memcpy(&lu_entry->lu_info->daddr, dst, sizeof(struct in6_addr));
		//lu_entry->lu_info->timestamp = jiffies;
		lu_entry->lu_info->counter = 1;

		/* We wait for 1 sec before sending LU. This is allowing the new address
		 *to be successfully configured and ready to be used*/
		setup_timer(&lu_entry->lu_info->timer, ilnp6_ret, (unsigned long)lu_entry);
		mod_timer(&lu_entry->lu_info->timer, jiffies + msecs_to_jiffies(lu_delay));

		// Add info in hash table, use CN's NID to derive a key (for now)
		hash_add(lu_info_table, &lu_entry->hlist, entry->ilcc_info->nid);
		print_lu_table();
		//spin_unlock(&lu_table_lock);

	  }

	  /*Add new L64 in ILCC*/
	  if (!in_ilcc) {

		pr_debug( "[ilnp6.c] ilnp6_rcv_ra: Add new local L64 to ilcc\n");
		tmp_l64_entry = kmem_cache_zalloc(l64_kmem, GFP_ATOMIC);
		tmp_l64_entry->l64 = new_l64;
		tmp_l64_entry->prec = L64_DEFAULT_PREC;
		tmp_l64_entry->flag = L64_VALID;	//will be active when the first LU is sent
		tmp_l64_entry->lifetime = lifetime; 	//same as prefer lifetime in RA
		//tmp_l64_entry->lu_sent = 1;
		//tmp_l64_entry->wait_for_ack = 1;
		setup_timer(&tmp_l64_entry->timer, ilcc_expired, (unsigned long)tmp_l64_entry);
		mod_timer(&tmp_l64_entry->timer, jiffies + lifetime*HZ);

		list_add_tail(&tmp_l64_entry->list, &entry->ilcc_info->l64_local->list);



	  }

      }
      print_ilcc();
      //spin_unlock(&ilcc_lock);


      return send;

}

/* Init function*/
int __init ilnp6_init(void)
{

	/* Create address cache from /etc/hosts*/
	addr_cache_kmem = kmem_cache_create("ilnp6_addr_cache",
					   sizeof(struct ilnp_addr_cache),
					   0, SLAB_HWCACHE_ALIGN,
					   NULL);
	if (!addr_cache_kmem) {
		pr_debug( "[ilnp6.c] ilnp6_init(): Error Creating cache\n");
		return -1;
	}

	addr_cache = kmem_cache_zalloc(addr_cache_kmem, GFP_ATOMIC);
	INIT_LIST_HEAD(&addr_cache->list);

	pr_debug( "[ilnp6.c] ilnp6_init(): Create ILNP cache\n");


	/* Create ILCC*/
	ilcc_kmem = kmem_cache_create("ilnp6_ilcc",
					   sizeof(struct ilcc_table),
					   0, SLAB_HWCACHE_ALIGN,
					   NULL);
	if (!ilcc_kmem) {
		pr_debug( "[ilnp6.c] ilnp6_init(): Error Creating ILCC\n");
		return -1;
	}

	//ilcc = kmem_cache_zalloc(ilcc_kmem, GFP_ATOMIC);
	//INIT_LIST_HEAD(&ilcc->list);
	hash_init(ilcc_info_table);


	l64_kmem = kmem_cache_create("ilnp6_l64_for_ilcc",
					   sizeof(struct l64_info),
					   0, SLAB_HWCACHE_ALIGN,
					   NULL);
	if (!l64_kmem) {
		pr_debug( "[ilnp6.c] ilnp6_init(): Error Creating L64 for ILCC\n");
		return -1;
	}

	pr_debug( "[ilnp6.c] ilnp6_init(): Create ILCC\n");


	/* Create LU cache to perform retransmission*/
	lu_cache_kmem = kmem_cache_create("ilnp6_lu_table",
					   sizeof(struct lu_table),
					   0, SLAB_HWCACHE_ALIGN,
					   NULL);
	if (!lu_cache_kmem) {
		pr_debug( "[ilnp6.c] ilnp6_init(): Error Creating LU cache\n");
		return -1;
	}

	//lu_info_table = kmem_cache_zalloc(lu_cache_kmem, GFP_ATOMIC);
	hash_init(lu_info_table);
	//INIT_LIST_HEAD(&lu_info_cache->list);

	pr_debug( "[ilnp6.c] ilnp6_init(): Create LU cache\n");

	cur_prefix = kmalloc(sizeof(struct in6_addr), GFP_KERNEL);
	memset(cur_prefix, 0, sizeof(struct in6_addr));

	struct netlink_kernel_cfg cfg = {
	    .input = nl_data_ready,

	};

	nl_sk = netlink_kernel_create(&init_net, NETLINK_ILNP, &cfg);

	if (nl_sk == NULL) {
	      pr_alert("[ilnp6.c] ilnp6_init(): ilnp6 - Error Netlink Socket\n");
	      return -1;
	}

	pr_debug( "[ilnp6.c] ilnp6_init(): Create Netlink Socket\n");

	/*Create a kernel thread to check the cache if any enrties are expired*/
	char name[]="ilnp cache checker";
	thread1 = kthread_run(check_cache,NULL,name);

	/* Sysctl varible for handoff mode: 0 = soft handoff, 1 = hard_handoff*/
	ilnp_table_header = register_sysctl_table(ilnp_root_table);
	pr_alert("[ilnp6.c] ilnp6_init(): ilnp6 - sysctl variable added\n");

	l64_home = 0;

	return 0;



}

/* Cleanup function*/
void ilnp6_cleanup(void)
{
	struct ilnp_addr_cache *entry, *next;
 	struct ilcc_table *ilcc_entry;
 	struct lu_table *lu_entry;
	int i;
	struct hlist_node *tmp;

	kthread_stop(thread1);

	pr_debug( "[ilnp6.c] ilnp6_cleanup(): Destroy ILNP cache\n");
	list_for_each_entry_safe(entry, next, &addr_cache->list, list) {
	      list_del(&entry->list);
	      kmem_cache_free(addr_cache_kmem, entry);
	}
	kmem_cache_destroy(addr_cache_kmem);

	pr_debug( "[ilnp6.c] ilnp6_cleanup(): Destroy ILCC\n");
	hash_for_each_safe(ilcc_info_table, i, tmp, ilcc_entry, hlist) {
	      kfree(ilcc_entry->ilcc_info);
	      hash_del(&ilcc_entry->hlist);
	      kmem_cache_free(ilcc_kmem, ilcc_entry);
	}
	kmem_cache_destroy(ilcc_kmem);

	pr_debug( "[ilnp6.c] ilnp6_cleanup(): Destroy LU cache\n");
	hash_for_each_safe(lu_info_table, i, tmp, lu_entry, hlist) {
	      kfree(lu_entry->lu_info);
	      hash_del(&lu_entry->hlist);
	      kmem_cache_free(lu_cache_kmem, lu_entry);
	}
	kmem_cache_destroy(lu_cache_kmem);

	pr_debug( "[ilnp6.c] ilnp6_cleanup(): Close Netlink Socket\n");
	sock_release(nl_sk->sk_socket);

	unregister_sysctl_table(ilnp_table_header);
	pr_alert("[ilnp6.c] ilnp6_cleanup(): ilnp6 - sysctl variable removed\n");


}
