#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#define DRIVER_AUTHOR "Mohammad Heib <goody698@gmail.com>"
#define DRIVER_DESC   "incoming traffic sniffing - basic implementation"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);

static unsigned int my_nf_hookfn(void *priv,
              struct sk_buff *skb,
              const struct nf_hook_state *state)
{
	struct iphdr *ip4h = NULL;
	struct ipv6hdr *ip6h = NULL;
	char saddr[16], daddr[16];
	struct tcphdr *tcp = NULL;
	struct udphdr *udp = NULL;

	if (skb->protocol == htons(ETH_P_IP)) { /* IPv4 */
		ip4h = ip_hdr(skb);
		snprintf(saddr, 16, "%pI4", &ip4h->saddr);
		snprintf(daddr, 16, "%pI4", &ip4h->daddr);

		pr_info("HDR_NAME[ipv4]: TTL = %d\n", ip4h->ttl);
		pr_info("HDR_NAME[ipv4]: saddr = %s\n", saddr);
		pr_info("HDR_NAME[ipv4]: daddr = %s\n", daddr);
		pr_info("HDR_NAME[ipv4]: checksum = 0x%X", ip4h->check);
		pr_info("HDR_NAME[ipv4]: id = 0x%X", ip4h->check);
		if (ip4h->protocol == IPPROTO_TCP){
			tcp = (struct tcphdr*)((__u32*)ip4h + ip4h->ihl);
		}else if (ip4h->protocol == IPPROTO_UDP){

			udp = (struct udphdr*)((__u32*)ip4h + ip4h->ihl);
		}

	} else if(skb->protocol == htons(ETH_P_IPV6)){/* IPv6 */
		ip6h = ipv6_hdr(skb);
		snprintf(saddr, 16, "%pI4", &ip6h->saddr);
		snprintf(daddr, 16, "%pI4", &ip6h->daddr);

		pr_info("HDR_NAME[ipv4]: HOPLIMIT = %d\n", ip6h->hop_limit);
		pr_info("HDR_NAME[ipv4]: saddr = %s\n", saddr);
		pr_info("HDR_NAME[ipv4]: daddr = %s\n", daddr);
		if (ip6h->nexthdr == IPPROTO_TCP){
			tcp = tcp_hdr(skb);
		}else if (ip6h->nexthdr == IPPROTO_UDP){

			udp = udp_hdr(skb);
		}
	}	


	return NF_ACCEPT;
}

static struct nf_hook_ops my_nfho = {
      .hook        = my_nf_hookfn,
      .hooknum     = NF_INET_LOCAL_OUT|NF_INET_LOCAL_IN,
      .pf          = PF_INET,
      .priority    = NF_IP_PRI_FIRST
};

int __init nf_sniff_init(void)
{
     
	return nf_register_net_hook(&init_net, &my_nfho);
}

void __exit nf_sniff_exit(void)
{
      nf_unregister_net_hook(&init_net, &my_nfho);
}

module_init(nf_sniff_init);
module_exit(nf_sniff_exit);
