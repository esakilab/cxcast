#### memo

`cxcast` is a userland application to encapsulte BUM packets in specified VXLAN. It helps VXLAN devices that do not have Multicast based MAC/VTEP learning.


`cxcast` creates a tap interface, and encapsulates BUM packets transmitted to the tap interface in specified VXLAN packets.

	 ./cxcast: invalid option -- 'h'
	 usage of cxcast
	 	 -t [IFNAME] : tap interface name
	 	 -v [VNI]    : VNI for tap interface
	 	 -i [IFNAME] : underlay interface name (optional)
	 	 -m MACADDR_MCASTADDR_SRCADDR : mac/mcast/source mapping

One tap interface is one VNI. Source and Destination UDP port numbers are 4789. UDP checksum is 0. MACADDR of `-m` options means source MAC address of BUM packets. `ff:ff:ff:ff:ff:ff` matches all source MAC addresses (defualt entry). Multiple `-m` options are permitted. To encapsulates BUM packets of multiple segments, run multiple `cxcast` processes at the same time.

	 % sudo ./cxcast -t vxlan10 -v 10 -m ff:ff:ff:ff:ff:ff_239.0.0.1_172.16.10.11 &
	 main [414] install MAC_MCAST_SRC entry ff:ff:ff:ff:ff:ff_239.0.0.1_172.16.10.11
	 mac_list_add [111] install defualt MAC entry, MCAST=239.0.0.1 SRC=172.16.10.11
	 main [455] tap_fd:3, raw_fd:4
	 
	 % ifconfig vxlan10
	 vxlan10   Link encap:Ethernet  HWaddr a2:98:d6:d9:f2:8a  
	           inet6 addr: fe80::a098:d6ff:fed9:f28a/64 Scope:Link
	           UP BROADCAST RUNNING  MTU:1500  Metric:1
	           RX packets:0 errors:0 dropped:0 overruns:0 frame:0
	           TX packets:6 errors:0 dropped:0 overruns:0 carrier:0
	           collisions:0 txqueuelen:500 
	           RX bytes:0 (0.0 B)  TX bytes:508 (508.0 B)
	 %

Then, create `br` interface, bridge the segument that you want to encap BUM packets and the tap interface.

	 % sudo brctl addbr br0
	 % sudo ip link set dev br0 up
	 % sudo brctl addif br0 eth2
	 % sudo brctl addif br0 vxlan10
	 % brctl show
	 bridge name	bridge id		STP enabled	interfaces
	 br0		8000.a298d6d9f28a	no		eth2
	 							vxlan10
	 %

All BUM packets from eth2 are encapsulated in VXLAN header, UDP header and IP header with source 172.16.10.11 destination 239.0.0.1.



To join multicast address group (send IGMP report for snooping), use `socat`.

- `apt-get install socat`
- `socat STDIO UDP4-RECV:1234,ip-add-membership=239.0.0.1:eth0`

