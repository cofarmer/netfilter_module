
// 
// Date: 2016-12-26
// Author: Yanfei Zhang
//
// Description: gateway, for forward packets
//

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/init.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_l3proto.h>
#include <net/netfilter/nf_nat_l4proto.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_helper.h>

#include <net/sock.h>

#include "../inc/pack_header.h"

unsigned int handle_udp(struct sk_buff *sk_buf)
{
	//
	// TODO: 
	//		UDP数据包加头（同TCP方式）
	//		将最后一跳的UDP服务器程序放在本地运行（修改其中的加解密顺序）
	//		iptables 新建规则将UDP的包转向本地一个端口（UDP服务器程序监听的端口）
	//

	struct iphdr *ip_header = NULL;
	struct udphdr *udp_header = NULL;
	int iptotal_len = 0;
	int iphdr_len = 0;
	int udphdr_len = 0;
	struct nf_conn *ct = NULL;
	enum ip_conntrack_info ctinfo;

	char * payload = NULL;
	char *_payload = NULL;
	int payload_len = 0;

	struct _msg_header *msgheader = NULL;

	ip_header = ip_hdr(sk_buf);
	if(!ip_header || ip_header->protocol != IPPROTO_UDP)
	{
		return NF_DROP;
	}

	iphdr_len = ip_header->ihl * 4;
	iptotal_len = ntohs(ip_header->tot_len);

	udp_header = (void *)ip_header + iphdr_len;
	udphdr_len = 8;

	if ( ntohs(udp_header->dest) != 6253)
	{
		return NF_ACCEPT;
	}

	payload = (char *)udp_header + udphdr_len;
	payload_len = ntohs(udp_header->len) - udphdr_len;
	if (!payload_len)
	{
		return NF_ACCEPT;
	}

	_payload = (char *)kmalloc(payload_len + sizeof(struct _msg_header) + 1, GFP_KERNEL);
	if (_payload)
	{
		msgheader = (struct _msg_header *)_payload;

		memcpy(_payload + sizeof(struct _msg_header), payload, payload_len);

		ct = nf_ct_get(sk_buf, &ctinfo);
		if (ct)
		{
			// construct msgheader
			msgheader->direction = 0;
			msgheader->reserved = 0;
			msgheader->tunnel = 0;
			msgheader->flowtuple.saddr = 0; //ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.src.u3.ip;
			msgheader->flowtuple.sport = 0; //ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.src.u.all;
			msgheader->flowtuple.daddr = ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.dst.u3.ip;
			msgheader->flowtuple.dport = ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.dst.u.all;

			// 
			// TODO: DNS劫持
			//

			//printk(KERN_INFO"handle_udp: %pI4:%u ==> %pI4:%u \n", 
			//	&msgheader->flowtuple.saddr, 
			//	ntohs(msgheader->flowtuple.sport),
			//	&msgheader->flowtuple.daddr,
			//	ntohs(msgheader->flowtuple.dport));


			// 加入连接跟踪信息，内核版本4.**的会自动修正seq和ack
			//nfct_seqadj_ext_add(ct);

			// modify packet(expand packet size and insert msgheader into head)
			if(nf_nat_mangle_udp_packet(
				sk_buf, 
				ct, 
				ctinfo, 
				iphdr_len, 
				0, 
				payload_len,
				_payload,
				payload_len + sizeof(struct _msg_header)
				))
			{
				//printk(KERN_INFO"nf_nat_manglr_udp_packet ok \n");
			}
			else
			{
				printk(KERN_INFO"nf_nat_manglr_udp_packet error \n");
				kfree(_payload);
				return NF_DROP;
			}
		}

		kfree(_payload);

		return NF_ACCEPT;
	}

	return NF_DROP;
}


static unsigned int hook_proc(
		unsigned int hook_num,
		struct sk_buff *sk_buf,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *)
		)
{
	struct iphdr *ip_header = NULL;

	// IP数据包frag合并
	if (skb_is_nonlinear(sk_buf))
	{
		if ( 0 != skb_linearize(sk_buf))
		{
			printk(KERN_INFO"skb_linearize failed \n");
			return NF_ACCEPT;
		}
	}
	
	ip_header = ip_hdr(sk_buf);
	if(ip_header != NULL)
	{
		switch (ip_header->protocol)
		{
		case IPPROTO_TCP:
			break;
		case IPPROTO_UDP:
			return handle_udp(sk_buf);
			break;
		default:
			break;
		}
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops hook_ops_proc = {
	.hook = hook_proc,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_MANGLE,
	//.owner = NULL,
};

static int __init filter_packet_init(void)
{
	if(nf_register_hook(&hook_ops_proc))
	{
		printk(KERN_ERR"nf_register_hook pre routing failed \n");
		return -1;
	}

	printk(KERN_INFO"hook regist succeed! \n");

	return 0;
}

//
//
static void __exit filter_packet_exit(void)
{
	nf_unregister_hook(&hook_ops_proc);

	printk(KERN_INFO"hook unregist succeed! \n");

	return ;
}


module_init(filter_packet_init);
module_exit(filter_packet_exit);
MODULE_AUTHOR("Noema");
MODULE_LICENSE("GPL");
