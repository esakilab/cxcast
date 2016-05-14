/* cxcast.c 
 *  - Encapsulating BUM traffic into Specified VXLAN.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <inttypes.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "list.h"

#define UDP_PORT	4789
#define POLL_TIMEOUT	10 * 1000


#define D(_fmt, ...)						    \
	do {							    \
		fprintf(stdout, "%s [%d] " _fmt "\n",		    \
			__FUNCTION__, __LINE__, ##__VA_ARGS__);     \
	} while (0)


struct vxlanhdr {
	__u32	vx_flags;
	__u32	vx_vni;
} __attribute__ ((__packed__));

#define VXLAN_HEADROOM (sizeof (struct ip) + sizeof (struct udphdr) + \
			sizeof (struct vxlanhdr))

struct mac_list {
	struct list_head list;	/* cxcast->mac_list */

	__u8 mac[ETH_ALEN];
	struct in_addr src_addr;
	struct in_addr mcast_addr;
	struct sockaddr_storage mcast_saddr;
};

struct cxcast {
	int tap_fd;	/* to recv BUM packets from tap interface */
	int raw_fd;	/* to send encaped BUM packet */
	int udp_fd;	/* for multicast join*/

	__u32 vni;
	char dev[IFNAMSIZ];		/* tap interface name */
	char *link;			/* underlay link interface name */
	struct list_head mac_list;	/* MAC->SRC mapping table */
	struct mac_list *bcast;		/* default mac entry */
};

void
mac_list_add (struct cxcast *cxc, __u8 *mac, struct in_addr mcast_addr,
	      struct in_addr src_addr)
{
	struct mac_list *mc;
	struct sockaddr_in *saddr;

	mc = (struct mac_list *) malloc (sizeof (*mc));
	memset (mc, 0, sizeof (*mc));

	memcpy (mc->mac, mac, ETH_ALEN);
	mc->src_addr	= src_addr;
	mc->mcast_addr	= mcast_addr;

	saddr = (struct sockaddr_in *)&mc->mcast_saddr;
	saddr->sin_family = AF_INET;
	saddr->sin_port = IPPROTO_UDP;
	saddr->sin_addr = mcast_addr;

	if (mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
	    mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF) {
		/* broadcast mac entry means deafult entry */
		char mcast[16], src[16];
		inet_ntop (AF_INET, &mcast_addr, mcast, sizeof (mcast));
		inet_ntop (AF_INET, &src_addr, src, sizeof (src));
		D ("install defualt MAC entry, MCAST=%s SRC=%s", mcast, src);
		cxc->bcast = mc;
		return;
	}

	list_add (&cxc->mac_list, &mc->list);

	return;
}

struct mac_list *
mac_list_find (struct cxcast *cxc, __u8 *mac)
{
	struct mac_list *mc;

	list_for_each_entry (mc, &cxc->mac_list, list) {
		if (memcmp (mc->mac, mac, ETH_ALEN) == 0)
			return mc;
	}

	return cxc->bcast;
}

int
tap_alloc (char *dev)
{
	/* create tap interface */

	int fd;
	struct ifreq ifr;

	if ((fd = open ("/dev/net/tun", O_RDWR)) < 0) {
		D ("failed to open /dev/net_tun");
		return -1;
	}

	memset (&ifr, 0, sizeof (ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy (ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl (fd, TUNSETIFF, (void *)&ifr) < 0) {
		D ("failed to allocate \"%s\"", dev);
		perror ("ioctl");
		close (fd);
		return -1;
	}

	return fd;
}

int
tap_up (char *dev)
{
	int udp_fd;
	struct ifreq ifr;

	if ((udp_fd = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
		err (EXIT_FAILURE, "failed to open udp socket");

	memset (&ifr, 0, sizeof (ifr));
	ifr.ifr_flags = IFF_UP;
	strncpy (ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl (udp_fd, SIOCSIFFLAGS, (void *)&ifr) < 0) {
		D ("faield to up \"%s\"", dev);
		close (udp_fd);
		return -1;
	}

	close (udp_fd);

	return 0;
}

int
raw_socket_create (char *link)
{
	int fd, on = 1;

	if ((fd = socket (AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
		D ("faield to raw socket");
		return -1;
	}

	if (setsockopt (fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
		D ("faield to set sockop HDRINCL");
		close (fd);
		return -1;
	}

	if (link) {
		if (setsockopt (fd, SOL_SOCKET, SO_BINDTODEVICE, link,
				strlen (link) + 1) < 0) {
			D ("faield to set link to \"%s\"", link);
			close (fd);
			return -1;
		}
	}

	return fd;
}

int
udp_socket_create (void)
{
	int fd;

	if ((fd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		D ("failed to create udp socket");
		perror ("socket");
		return -1;
	}

	return fd;
}

int
getifaddr (char * dev, struct in_addr *ifaddr)
{
	int fd;
	struct ifreq ifr;
	struct sockaddr_in * addr;

	fd = socket (AF_INET, SOCK_DGRAM, 0);

	memset (&ifr, 0, sizeof (ifr));
	strncpy (ifr.ifr_name, dev, IFNAMSIZ - 1);

	if (ioctl (fd, SIOCGIFADDR, &ifr) < 0) {
		D ("faield to get ifaddr for %s", dev);
		return -1;
	}

	close (fd);

	addr = (struct sockaddr_in *) &(ifr.ifr_addr);

	*ifaddr = addr->sin_addr;

	return 0;
}

int
multicast_join (int fd, struct in_addr mcast_addr, char *link)
{
	struct ip_mreq mreq;

	memset (&mreq, 0, sizeof (mreq));
	mreq.imr_multiaddr = mcast_addr;
	if (link)
		getifaddr (link, &mreq.imr_interface);
	
	if (setsockopt (fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
			&mreq, sizeof (mreq)) < 0) {
		D ("faield to join \"%s\"", inet_ntoa (mcast_addr));
		return -1;
	}

	if (link) {
		if (setsockopt (fd, IPPROTO_IP, IP_MULTICAST_IF,
				&mreq, sizeof (mreq)) < 0) {
			D ("faield to set multicast interface %s for %s",
			   link, inet_ntoa (mcast_addr));
			return -1;
		}
	}

	return 0;
}

void
cxcast_multicast_join (struct cxcast *cxc)
{
	struct mac_list *mc;

	if (cxc->bcast) {
		mc = cxc->bcast;
		D ("join multicast %s", inet_ntoa (mc->mcast_addr));
		//multicast_join (cxc->udp_fd, mc->mcast_addr, cxc->link);
	}

	list_for_each_entry (mc, &cxc->mac_list, list) {
		D ("join multicast %s", inet_ntoa (mc->mcast_addr));
		multicast_join (cxc->udp_fd, mc->mcast_addr, cxc->link);
	}
}

int
split_mac_mcast_src (char *arg, __u8 *mac_addr, struct in_addr *mcast_addr,
		     struct in_addr *src_addr)
{
	/* arg = MAC_MCAST_SRC */

	int len, n, ret, mac_int[6];
	char *p, *mac, *mcast, *src;
	len = strlen (arg) + 1;

	for (p = arg, mac = arg, mcast = NULL, src = NULL, n = 0;
	     n < len; n++, p++) {
		if (*p == '_') {
			if (mcast == NULL) 
				mcast = p + 1;
			else if (src == NULL)
				src = p + 1;
			*p = '\0';
		}
	}
	
	ret = inet_pton (AF_INET, mcast, mcast_addr);
	if (ret < 1) {
		D ("failed to parse mcast addr from %s", optarg);
		return -1;
	}

	ret = inet_pton (AF_INET, src, src_addr);
	if (ret < 1) {
		D ("failed to parse source addr from %s", optarg);
		return -1;
	}

	/* XXX: ascii to mac */
	ret = sscanf (mac, "%x:%x:%x:%x:%x:%x",
		      &mac_int[0], &mac_int[1], &mac_int[2],
		      &mac_int[3], &mac_int[4], &mac_int[5]);
	if (ret < 1) {
		D ("faield to parse mac addr from %s", optarg);
		return -1;
	}
	mac_addr[0] = mac_int[0];
	mac_addr[1] = mac_int[1];
	mac_addr[2] = mac_int[2];
	mac_addr[3] = mac_int[3];
	mac_addr[4] = mac_int[4];
	mac_addr[5] = mac_int[5];

	return 0;
}

void
usage (void)
{
	printf ("usage of cxcast\n"
		"\t -t [IFNAME] : tap interface name\n"
		"\t -v [VNI]    : VNI for tap interface\n"
		"\t -i [IFNAME] : underlay interface name (optional)\n"
		"\t -m MACADDR_MCASTADDR_SRCADDR : mac/mcast/source mapping\n"
		"\n"
		);
}

/* from netmap pkt-gen.c */

static uint16_t
checksum(const void * data, uint16_t len, uint32_t sum)
{
	const uint8_t *addr = data;
	uint32_t i;

	/* Checksum all the pairs of bytes first... */
	for (i = 0; i < (len & ~1U); i += 2) {
		sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	/*
         * If there's a single byte left over, checksum it, too.
         * Network byte order is big-endian, so the remaining byte is
         * the high byte.
         */

	if (i < len) {
		sum += addr[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}

	return sum;
}

static u_int16_t
wrapsum(u_int32_t sum)
{
	sum = ~sum & 0xFFFF;
	return (htons(sum));
}

int
bum_encap_out (struct cxcast *cxc, struct ethhdr *eth, int len)
{
	int ret;
	char buf[9126 + VXLAN_HEADROOM];
	struct ip *ip;
	struct udphdr *udp;
	struct vxlanhdr *vxh;
	struct mac_list *mc;

	mc = mac_list_find (cxc, eth->h_source);
	if (!mc)
		return -1;

	ip = (struct ip *)buf;
	udp = (struct udphdr *)(ip + 1);
	vxh = (struct vxlanhdr *)(udp + 1);

	vxh->vx_flags = htonl (0x08000000); /* VNI bit */
	vxh->vx_vni = htonl (cxc->vni << 8);

	udp->source = htons (UDP_PORT);
	udp->dest = htons (UDP_PORT);
	udp->len = htons (len + sizeof (*vxh) + sizeof (*udp));
	udp->check = 0;

	ip->ip_v = IPVERSION;
	ip->ip_hl = 5;
	ip->ip_id = 0;
	ip->ip_tos = 0;	/* XXX: IPTOS_LOWDELAY? */
	ip->ip_len = htons (len + VXLAN_HEADROOM);
	ip->ip_off = htons (IP_DF);
	ip->ip_p = IPPROTO_UDP;
	ip->ip_dst = mc->mcast_addr;
	ip->ip_src = mc->src_addr;
	ip->ip_sum = 0;
	ip->ip_sum = wrapsum (checksum (ip, sizeof (*ip), 0));

	memcpy (vxh + 1, eth, len);

	ret = sendto (cxc->raw_fd, buf, len + VXLAN_HEADROOM, 0,
		      (struct sockaddr *)&mc->mcast_saddr,
		      sizeof (mc->mcast_saddr));
	if (ret < 0) {
		D ("failed to send encaped packet "
		   "%02x:%02x:%02x:%02x:%02x:%02x",
		   eth->h_source[0], eth->h_source[1], eth->h_source[2],
		   eth->h_source[3], eth->h_source[4], eth->h_source[5]);
		perror ("sendto");
	}

	return ret;
}

void
cxcast_thread (struct cxcast *cxc)
{
	int len;
	char buf[9216];
	struct pollfd x[1];
	struct ethhdr *eth;

	x[0].fd = cxc->tap_fd;
	x[0].events = POLLIN;

	while (1) {
		if (poll (x, 1, POLL_TIMEOUT) == 0)
			continue;

		/* a packet is transmitted to tap interface */
		len = read (cxc->tap_fd, buf, sizeof (buf));
		if (len < 0) {
			D ("failed to read packet from tap_fd.");
			perror ("read");
		}

		eth = (struct ethhdr *)buf;

		/* is this multicast frame? (inidividual/group bit) */
		if (eth->h_source[5] & 0x01)
			bum_encap_out (cxc, eth, len);

	}

	return;
}

int
main (int argc, char **argv)
{
	int ch, ret;
	__u8 mac[ETH_ALEN];
	struct in_addr mcast_addr, src_addr;
	struct cxcast cxcast;
	
	memset (&cxcast, 0, sizeof (cxcast));
	INIT_LIST_HEAD (&cxcast.mac_list);

	while ((ch = getopt (argc, argv, "m:t:v:i:")) != -1) {
		switch (ch) {
		case 'm' :
			D ("install MAC_MCAST_SRC entry %s", optarg);
			ret = split_mac_mcast_src (optarg, mac,
						   &mcast_addr, &src_addr);
			if (ret < 0)
				return -1;

			mac_list_add (&cxcast, mac, mcast_addr, src_addr);
			break;

		case 't':
			strncpy (cxcast.dev, optarg, IFNAMSIZ);
			break;

		case 'i' :
			cxcast.link = optarg;
			break;

		case 'v' :
			cxcast.vni = atoi (optarg);
			if (cxcast.vni < 0 || cxcast.vni > 16777216) {
				D ("invalid vni value \"%s\"", optarg);
				return -1;
			}
			break;

		default:
			usage ();
			return -1;
		}
	}

	cxcast.tap_fd = tap_alloc (cxcast.dev);
	if (cxcast.tap_fd < 0)
		return -1;

	tap_up (cxcast.dev);

	cxcast.raw_fd = raw_socket_create (cxcast.link);
	if (cxcast.raw_fd < 0)
		return -1;

	cxcast.udp_fd = udp_socket_create ();
	if (cxcast.udp_fd < 0)
		return -1;

	D ("tap_fd:%d, raw_fd:%d, udp_fd:%d",
	   cxcast.tap_fd, cxcast.raw_fd, cxcast.udp_fd);

	cxcast_multicast_join (&cxcast);

	cxcast_thread (&cxcast);

	return 0;
}
