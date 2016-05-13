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
#include <inttypes.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <net/if.h>

#include "list.h"

#define UDPPORT	4789


#define D(_fmt, ...)						    \
	do {							    \
		fprintf(stdout, "%s [%d] " _fmt "\n",		    \
			__FUNCTION__, __LINE__, ##__VA_ARGS__);     \
	} while (0)


struct vxlanhdr {
	__u8	vxlan_flags;
	__u8	vxlan_vni;
};

struct cxcast {
	int tap_fd;	/* to recv BUM packets from tap interface */
	int raw_fd;	/* to send encaped BUM packet */
	int udp_fd;	/* for multicast join*/

	__u32 vni;
	char devname[IFNAMSIZ];
	struct list_head mac_list;	/* MAC->SRC mapping table */
};

struct mac_list {
	struct list_head list;	/* cxcast->mac_list */

	__u8 mac[ETH_ALEN];
	struct in_addr src_addr;
	struct in_addr mcast_addr;
	struct sockaddr_storage mcast_saddr;
};

void
mac_list_add (struct cxcast *cxc, __u8 *mac, struct in_addr src_addr,
	      struct in_addr mcast_addr)
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
	saddr->sin_addr = mcast_addr;

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

	return NULL;
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

	if ((fd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		D ("faield to raw socket");
		return -1;
	}

	if (setsockopt (fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
		D ("faield to set sockop HDRINCL");
		close (fd);
		return -1;
	}

	if (setsockopt (fd, SOL_SOCKET, SO_BINDTODEVICE, link,
			strlen (link) + 1) < 0) {
		D ("faield to set link to \"%s\"", link);
		close (fd);
		return -1;
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
	getifaddr (link, &mreq.imr_interface);
	
	if (setsockopt (fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
			&mreq, sizeof (mreq)) < 0) {
		D ("faield to join \"%s\"", inet_ntoa (mcast_addr));
		return -1;
	}

	if (setsockopt (fd, IPPROTO_IP, IP_MULTICAST_IF,
			&mreq, sizeof (mreq)) < 0) {
		D ("faield to set multicast interface %s for %s",
		   link, inet_ntoa (mcast_addr));
		return -1;
	}

	return 0;
}


int
main (int argc, char **argv)
{
	return 0;
}
