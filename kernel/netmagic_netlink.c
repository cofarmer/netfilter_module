
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
#include <net/netlink.h>

#include "../inc/pack_header.h"


#define NETLINK_USER  22
#define USER_MSG    (NETLINK_USER + 1)
#define USER_PORT   50
static struct sock *netlinkfd = NULL;

int stringlength(char *s)
{
    int slen = 0;
    for(; *s; s++)
    {
        slen++;
    }
    return slen;
}

int send_msg(int8_t *pbuf, uint16_t len)
{
    struct sk_buff *nl_skb;
    struct nlmsghdr *nlh;

    int ret;

    nl_skb = nlmsg_new(len, GFP_ATOMIC);
    if(!nl_skb)
    {
        printk("netlink_alloc_skb error\n");
        return -1;
    }

    nlh = nlmsg_put(nl_skb, 0, 0, USER_MSG, len, 0);
    if(nlh == NULL)
    {
        printk("nlmsg_put() error\n");
        nlmsg_free(nl_skb);
        return -1;
    }
    memcpy(nlmsg_data(nlh), pbuf, len);

    ret = netlink_unicast(netlinkfd, nl_skb, USER_PORT, MSG_WAITFORONE);

    return ret;
}


static void recv_cb(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    void *data = NULL;

    printk("skb->len:%u\n", skb->len);
    if(skb->len >= nlmsg_total_size(0))
    {
        nlh = nlmsg_hdr(skb);
        data = NLMSG_DATA(nlh);
        if(data)
        {
            printk("kernel receive data: %s\n", (int8_t *)data);

            //send_msg(data, nlmsg_len(nlh));
        }
    }
} 

struct netlink_kernel_cfg cfg = 
{
    .input = recv_cb,
};
// Initialize netlink
int netlink_init(void)
{
	printk("init netlink_demo!\n");

    netlinkfd = netlink_kernel_create(&init_net, USER_MSG, &cfg);
    if(!netlinkfd)
    {
        printk(KERN_ERR "can not create a netlink socket!\n");
        return -1;
    }

    printk("netlink demo init ok!\n");
    return 0;
    
}
static void netlink_exit(void)
{
    if(netlinkfd != NULL){
        sock_release(netlinkfd->sk_socket);
    }
    printk("my_net_link: self module exited\n");
}


//
//
void data_encrypt(const char *buf, unsigned int buflen)
{
	char *_buf = NULL;
	int idx = 0;

	if (!buf)
	{
		return ;
	}

	_buf = (char *)buf;
	for (; idx<buflen; ++idx)
	{
		_buf[idx] ^= 0x89;
	}
	
	return ;
}


// convert IPv4 address number to string
//
char *inet_v4_ntoa_x(struct in_addr *iaddr, char *buf, int buflen)
{
	unsigned char *ptr = NULL;

	if(iaddr == NULL)
	{
		return NULL;
	}
	if(buflen < 16)
	{
		return NULL;
	}
	
	ptr = (unsigned char *)iaddr;
	sprintf(buf, "%d.%d.%d.%d", ptr[0] &0xff, ptr[1] & 0xff, ptr[2] & 0xff, ptr[3] & 0xff);

	return buf;
}

//
//
void print_mac_address(unsigned char *buf)
{
	char mac[64];

	if(!buf)
	{
		return ;
	}

	memset(mac, '\0', sizeof(mac));
	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", 
		buf[0],
		buf[1],
		buf[2],
		buf[3],
		buf[4],
		buf[5]
		);
	printk(KERN_INFO"%s \n", mac);

	return ;
}

unsigned int handle_tcp(struct sk_buff *sk_buf)
{
	struct iphdr *ip_header = NULL;
	struct tcphdr *tcp_header = NULL;
	int iptotal_len = 0;
	int iphdr_len = 0;
	int tcphdr_len = 0;
	struct nf_conn *ct = NULL;
	enum ip_conntrack_info ctinfo;
	struct ethhdr *eth_info = NULL;

	char * payload = NULL;
	char *_payload = NULL;
	int payload_len = 0;

	struct _dest_info *dinfo = NULL;

	// get source mac address
	eth_info = (struct ethhdr *)skb_mac_header(sk_buf);
	if(!eth_info)
	{
		printk(KERN_INFO"skb_mac_header failed \n");
		return NF_DROP;
	}

	ip_header = ip_hdr(sk_buf);
	if(!ip_header || ip_header->protocol != IPPROTO_TCP)
	{
		return NF_DROP;
	}

	iphdr_len = ip_header->ihl * 4;
	iptotal_len = ntohs(ip_header->tot_len);

	tcp_header = (void *)ip_header + iphdr_len;
	tcphdr_len = tcp_header->doff * 4;

	if ( ntohs(tcp_header->dest) != 6253)
	{
		return NF_ACCEPT;
	}

	//
	ct = nf_ct_get(sk_buf, &ctinfo);
	if (ct)
	{
		//IP_CT_NEW = 2;
		//IP_CT_ESTABLISHED = 0;
		//
		if (ctinfo == IP_CT_ESTABLISHED)
		{
			if (ct->status == 430 
				&& tcp_header->ack == 1 
				&& tcp_header->psh == 0 
				&& tcp_header->rst == 0
				&& tcp_header->fin == 0
				)
			{
				struct nl_data nd = {0};
				nd.ftuple.saddr = ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.src.u3.ip;
				nd.ftuple.sport = ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.src.u.all;
				nd.ftuple.daddr = ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.dst.u3.ip;
				nd.ftuple.dport = ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.dst.u.all;
				memcpy(nd.src_mac, eth_info->h_source, 6);
				//printk("%pI4:%d --> %pI4:%d \n", &nd.ftuple.saddr, ntohs(nd.ftuple.sport), &nd.ftuple.daddr, ntohs(nd.ftuple.dport));
				//printk("syn:%d, ack:%d, psh:%d, rst:%d, ct->status: %d \n", tcp_header->syn, tcp_header->ack, tcp_header->psh, tcp_header->rst, ct->status);
				send_msg(&nd, sizeof(nd));
			}
		}
	}

	//payload = (char *)tcp_header + tcphdr_len;
	//payload_len = iptotal_len - iphdr_len - tcphdr_len;
	//if (!payload_len)
	//{
	//	return NF_ACCEPT;
	//}

	//_payload = (char *)kmalloc(payload_len + sizeof(struct _dest_info) + 1, GFP_KERNEL);
	//if (!_payload)
	//{
	//	printk(KERN_INFO"error: kmalloc failed \n");
	//	return NF_DROP;
	//}

	//dinfo = (struct _dest_info *)_payload;

	//memcpy(_payload + sizeof(struct _dest_info), payload, payload_len);

	////ct = nf_ct_get(sk_buf, &ctinfo);
	//if (ct)
	//{
	//	// save destination address of destination
	//	dinfo->magic = D_MAGIC;
	//	dinfo->length = payload_len;
	//	dinfo->daddr = ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.dst.u3.ip;
	//	dinfo->dport = ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.dst.u.all;
	//	memcpy(dinfo->src_mac, eth_info->h_source, 6);
	//	dinfo->reserved = 0;

	//	//printk(KERN_INFO"handle_tcp: %pI4:%u \n", 
	//	//		&dinfo->daddr,
	//	//		ntohs(dinfo->dport));

	//	// NOTE: 加入连接跟踪信息，内核版本4.**的会自动修正seq和ack
	//	nfct_seqadj_ext_add(ct);

	//	// modify packet(expand packet size and insert dinfo into head)
	//	if(nf_nat_mangle_tcp_packet(
	//		sk_buf, 
	//		ct, 
	//		ctinfo, 
	//		iphdr_len, 
	//		0, 
	//		payload_len,
	//		_payload,
	//		payload_len + sizeof(struct _dest_info)
	//		))
	//	{
	//		//printk(KERN_INFO"nf_nat_manglr_tcp_packet ok \n");
	//	}
	//	else
	//	{
	//		printk(KERN_INFO"nf_nat_manglr_tcp_packet error \n");
	//		kfree(_payload);
	//		return NF_DROP;
	//	}
	//}
	//else
	//{
	//	printk(KERN_INFO"nf_ct_get failed. \n");
	//}

	//kfree(_payload);

	return NF_ACCEPT;
}

unsigned int handle_tcp2(struct sk_buff *sk_buf)
{
	struct iphdr *ip_header = NULL;
	struct tcphdr *tcp_header = NULL;
	int iptotal_len = 0;
	int iphdr_len = 0;
	int tcphdr_len = 0;
	struct nf_conn *ct = NULL;
	enum ip_conntrack_info ctinfo;
	struct ethhdr *eth_info = NULL;

	char * payload = NULL;
	char *_payload = NULL;
	int payload_len = 0;

	struct _dest_info *dinfo = NULL;


	// get source mac address
	eth_info = (struct ethhdr *)skb_mac_header(sk_buf);
	if(!eth_info)
	{
		printk(KERN_INFO"skb_mac_header failed \n");
		return NF_DROP;
	}
	print_mac_address(eth_info->h_source);
	print_mac_address(eth_info->h_dest);

	return NF_ACCEPT; 

	ip_header = ip_hdr(sk_buf);
	if(!ip_header || ip_header->protocol != IPPROTO_TCP)
	{
		return NF_DROP;
	}

	iphdr_len = ip_header->ihl * 4;
	iptotal_len = ntohs(ip_header->tot_len);

	tcp_header = (void *)ip_header + iphdr_len;
	tcphdr_len = tcp_header->doff * 4;

	if (ntohs(tcp_header->source) != 6253)
	{
		return NF_ACCEPT;
	}
	
	//
	ct = nf_ct_get(sk_buf, &ctinfo);
	if (ct)
	{
		//
		// IP_CT_ESTABLISHED = 0;
		// IP_CT_NEW = 2;
		// IP_CT_IS_REPLY = 3;
		// IP_CT_ESTABLISHED_REPLY = IP_CT_ESTABLISHED + IP_CT_IS_REPLY
		// file link: ..\linux-headers-4.4.0-53-generic\include\uapi\linux\netfilter\nf_conntrack_common.h
		//
		if (ctinfo == IP_CT_ESTABLISHED_REPLY)
		{
			if (tcp_header->syn == 1 && tcp_header->ack == 1 && ct->status == 426)
			{
				struct nl_data nd = {0};
				nd.ftuple.saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
				nd.ftuple.sport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
				nd.ftuple.daddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
				nd.ftuple.dport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
				memcpy(nd.src_mac, eth_info->h_dest, 6);
				print_mac_address(eth_info->h_dest);
				print_mac_address(eth_info->h_source);
				printk("%pI4:%d --> %pI4:%d \n", &nd.ftuple.saddr, ntohs(nd.ftuple.sport), &nd.ftuple.daddr, ntohs(nd.ftuple.dport));
				printk("syn:%d, ack:%d, psh:%d, rst:%d, ct->status: %d, ctinfo: %d\n", tcp_header->syn, tcp_header->ack, tcp_header->psh, tcp_header->rst, ct->status, ctinfo);
				send_msg(&nd, sizeof(nd));
			}
		}
	}
	else
	{
		printk("nf_ct_get failed \n");
	}

	return NF_ACCEPT;
}

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
	if ( 0 != skb_linearize(sk_buf))
	{
		printk(KERN_INFO"skb_linearize failed \n");
		return NF_ACCEPT;
	}
	
	ip_header = ip_hdr(sk_buf);
	if(ip_header != NULL)
	{
		switch (ip_header->protocol)
		{
		case IPPROTO_TCP:
			return handle_tcp(sk_buf);
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
static unsigned int hook_proc2(
		unsigned int hook_num,
		struct sk_buff *sk_buf,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *)
		)
{
	struct iphdr *ip_header = NULL;

	// IP数据包frag合并
	if ( 0 != skb_linearize(sk_buf))
	{
		printk(KERN_INFO"skb_linearize failed \n");
		return NF_ACCEPT;
	}
	
	ip_header = ip_hdr(sk_buf);
	if(ip_header != NULL)
	{
		switch (ip_header->protocol)
		{
		case IPPROTO_TCP:
			return handle_tcp2(sk_buf);
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

static struct nf_hook_ops hook_ops_proc2 = {
	.hook = hook_proc2,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_MANGLE,
	//.owner = NULL,
};
static int __init filter_packet_init(void)
{
	netlink_init();

	if(nf_register_hook(&hook_ops_proc))
	{
		printk(KERN_ERR"nf_register_hook pre routing failed \n");
		return -1;
	}

	//nf_register_hook(&hook_ops_proc2);

	printk(KERN_INFO"hook regist succeed! \n");

	return 0;
}

//
//
static void __exit filter_packet_exit(void)
{
	nf_unregister_hook(&hook_ops_proc);
	//nf_unregister_hook(&hook_ops_proc2);

	netlink_exit();

	printk(KERN_INFO"hook unregist succeed! \n");

	return ;
}


module_init(filter_packet_init);
module_exit(filter_packet_exit);
MODULE_AUTHOR("Noema");
MODULE_LICENSE("GPL");
