#ifndef ARP_SPOOF_H
#define ARP_SPOOF_H

#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <net/ethernet.h>
#include <netinet/in.h>

struct arphdr_bot{
    unsigned char	ar_sha[ETH_ALEN];	/* sender hardware address	*/
    unsigned char	ar_sip[4];		/* sender IP address		*/
    unsigned char	ar_tha[ETH_ALEN];	/* target hardware address	*/
    unsigned char	ar_tip[4];		/* target IP address		*/
}__attribute__((packed));

struct packetinfo{
    unsigned char   eth_dha[ETH_ALEN];  /* source hardware address  */
    unsigned char   eth_sha[ETH_ALEN];  /* destination hardware address */
    __be16  eth_proto; /*  ethernet protocol   */
    __be16  ar_op;  /*  arp opcode  */
    unsigned char	ar_sha[ETH_ALEN];	/* sender hardware address	*/
    unsigned char	ar_sip[4];		/* sender IP address		*/
    unsigned char	ar_tha[ETH_ALEN];	/* target hardware address	*/
    unsigned char	ar_tip[4];		/* target IP address		*/
};

#endif // ARP_SPOOF_H
