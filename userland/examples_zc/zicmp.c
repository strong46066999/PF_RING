struct vlan_hdr {
    u_int16_t	h_vlan_TCI;
    u_int16_t	h_vlan_encapsulated_proto;
};

struct arphdr {
    u_int16_t		ar_hrd;		/* format of hardware address	*/
    u_int16_t		ar_pro;		/* format of protocol address	*/
    unsigned char	ar_hln;		/* length of hardware address	*/
    unsigned char	ar_pln;		/* length of protocol address	*/
    u_int16_t		ar_op;		/* ARP opcode (command)		*/
};

struct icmphdr {
    uint8_t		type;
    uint8_t		code;
    u_int16_t	checksum;
    union {
        struct {
            u_int16_t	id;
            u_int16_t	sequence;
        } echo;
        u_int32_t	gateway;
        struct {
            u_int16_t	__unused;
            u_int16_t	mtu;
        } frag;
    } un;
};

#define ARPHRD_ETHER 	1		/* Ethernet 10Mbps		*/
#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_ECHO		8	/* Echo Request			*/

const char* arp_op_name(u_int16_t arp_op) {
    /* ARP protocol opcodes. */
#define	ARPOP_REQUEST	1		/* ARP request			*/
#define	ARPOP_REPLY	2		/* ARP reply			*/
#define	ARPOP_RREQUEST	3		/* RARP request			*/
#define	ARPOP_RREPLY	4		/* RARP reply			*/
#define	ARPOP_InREQUEST	8		/* InARP request		*/
#define	ARPOP_InREPLY	9		/* InARP reply			*/
#define	ARPOP_NAK	10		/* (ATM)ARP NAK			*/
    
    switch (arp_op ) {
    case ARPOP_REQUEST:
        return "ARP Request";
    case ARPOP_REPLY:
        return "ARP Reply";
    case ARPOP_RREQUEST:
        return "Reverse ARP Request";
    case ARPOP_RREPLY:
        return "Reverse ARP Reply";
    case ARPOP_InREQUEST:
        return "Peer Identify Request";
    case ARPOP_InREPLY:
        return "Peer Identify Reply";
    default:
        break;
    }
    return "Unkwown ARP op";
}

const char* ip_proto_name(u_int16_t ip_proto) {
    static const char * ip_proto_names[] = {
        "IP6HOPOPTS", /**< IP6 hop-by-hop options */
        "ICMP", 			/**< control message protocol */
        "IGMP", 			/**< group mgmt protocol */
        "GGP",				/**< gateway^2 (deprecated) */
        "IPv4", 			/**< IPv4 encapsulation */
        
        "UNASSIGNED",
        "TCP",				/**< transport control protocol */
        "ST", 				/**< Stream protocol II */
        "EGP",				/**< exterior gateway protocol */
        "PIGP", 			/**< private interior gateway */
        
        "RCC_MON",		/**< BBN RCC Monitoring */
        "NVPII",			/**< network voice protocol*/
        "PUP",				/**< pup */
        "ARGUS",			/**< Argus */
        "EMCON",			/**< EMCON */
        
        "XNET", 			/**< Cross Net Debugger */
        "CHAOS",			/**< Chaos*/
        "UDP",				/**< user datagram protocol */
        "MUX",				/**< Multiplexing */
        "DCN_MEAS", 	/**< DCN Measurement Subsystems */
        
        "HMP",				/**< Host Monitoring */
        "PRM",				/**< Packet Radio Measurement */
        "XNS_IDP",		/**< xns idp */
        "TRUNK1", 		/**< Trunk-1 */
        "TRUNK2", 		/**< Trunk-2 */
        
        "LEAF1",			/**< Leaf-1 */
        "LEAF2",			/**< Leaf-2 */
        "RDP",				/**< Reliable Data */
        "IRTP", 			/**< Reliable Transaction */
        "TP4",				/**< tp-4 w/ class negotiation */
        
        "BLT",				/**< Bulk Data Transfer */
        "NSP",				/**< Network Services */
        "INP",				/**< Merit Internodal */
        "SEP",				/**< Sequential Exchange */
        "3PC",				/**< Third Party Connect */
        
        "IDPR", 			/**< InterDomain Policy Routing */
        "XTP",				/**< XTP */
        "DDP",				/**< Datagram Delivery */
        "CMTP", 			/**< Control Message Transport */
        "TPXX", 			/**< TP++ Transport */
        
        "ILTP", 			/**< IL transport protocol */
        "IPv6_HDR", 	/**< IP6 header */
        "SDRP", 			/**< Source Demand Routing */
        "IPv6_RTG", 	/**< IP6 routing header */
        "IPv6_FRAG",	/**< IP6 fragmentation header */
        
        "IDRP", 			/**< InterDomain Routing*/
        "RSVP", 			/**< resource reservation */
        "GRE",				/**< General Routing Encap. */
        "MHRP", 			/**< Mobile Host Routing */
        "BHA",				/**< BHA */
        
        "ESP",				/**< IP6 Encap Sec. Payload */
        "AH", 				/**< IP6 Auth Header */
        "INLSP",			/**< Integ. Net Layer Security */
        "SWIPE",			/**< IP with encryption */
        "NHRP", 			/**< Next Hop Resolution */
        
        "UNASSIGNED",
        "UNASSIGNED",
        "UNASSIGNED",
        "ICMPv6", 		/**< ICMP6 */
        "IPv6NONEXT", /**< IP6 no next header */
        
        "Ipv6DSTOPTS",/**< IP6 destination option */
        "AHIP", 			/**< any host internal protocol */
        "CFTP", 			/**< CFTP */
        "HELLO",			/**< "hello" routing protocol */
        "SATEXPAK", 	/**< SATNET/Backroom EXPAK */
        
        "KRYPTOLAN",	/**< Kryptolan */
        "RVD",				/**< Remote Virtual Disk */
        "IPPC", 			/**< Pluribus Packet Core */
        "ADFS", 			/**< Any distributed FS */
        "SATMON", 		/**< Satnet Monitoring */
        
        "VISA", 			/**< VISA Protocol */
        "IPCV", 			/**< Packet Core Utility */
        "CPNX", 			/**< Comp. Prot. Net. Executive */
        "CPHB", 			/**< Comp. Prot. HeartBeat */
        "WSN",				/**< Wang Span Network */
        
        "PVP",				/**< Packet Video Protocol */
        "BRSATMON", 	/**< BackRoom SATNET Monitoring */
        "ND", 				/**< Sun net disk proto (temp.) */
        "WBMON",			/**< WIDEBAND Monitoring */
        "WBEXPAK",		/**< WIDEBAND EXPAK */
        
        "EON",				/**< ISO cnlp */
        "VMTP", 			/**< VMTP */
        "SVMTP",			/**< Secure VMTP */
        "VINES",			/**< Banyon VINES */
        "TTP",				/**< TTP */
        
        "IGP",				/**< NSFNET-IGP */
        "DGP",				/**< dissimilar gateway prot. */
        "TCF",				/**< TCF */
        "IGRP", 			/**< Cisco/GXS IGRP */
        "OSPFIGP",		/**< OSPFIGP */
        
        "SRPC", 			/**< Strite RPC protocol */
        "LARP", 			/**< Locus Address Resolution */
        "MTP",				/**< Multicast Transport */
        "AX25", 			/**< AX.25 Frames */
        "4IN4", 			/**< IP encapsulated in IP */
        
        "MICP", 			/**< Mobile Int.ing control */
        "SCCSP",			/**< Semaphore Comm. security */
        "ETHERIP",		/**< Ethernet IP encapsulation */
        "ENCAP",			/**< encapsulation header */
        "AES",				/**< any private encr. scheme */
        
        "GMTP", 			/**< GMTP */
        "IPCOMP", 		/**< payload compression (IPComp) */
        "UNASSIGNED",
        "UNASSIGNED",
        "PIM",				/**< Protocol Independent Mcast */
    };
    
    if (ip_proto < sizeof(ip_proto_names) / sizeof(ip_proto_names[0]))
        return ip_proto_names[ip_proto];
    switch (ip_proto) {
#ifdef IPPROTO_PGM
    case IPPROTO_PGM:  /**< PGM */
        return "PGM";
#endif
    case IPPROTO_SCTP:	/**< Stream Control Transport Protocol */
        return "SCTP";
#ifdef IPPROTO_DIVERT
    case IPPROTO_DIVERT: /**< divert pseudo-protocol */
        return "DIVERT";
#endif
    case IPPROTO_RAW: /**< raw IP packet */
        return "RAW";
    default:
        break;
    }
    return "UNASSIGNED";
}

void ipv4_addr_to_dot(u_int32_t be_ipv4_addr, char *buf) {
    u_int32_t ipv4_addr;
    
    ipv4_addr = ntohl(be_ipv4_addr);
    sprintf(buf, "%d.%d.%d.%d", (ipv4_addr >> 24) & 0xFF,
            (ipv4_addr >> 16) & 0xFF, (ipv4_addr >> 8) & 0xFF,
            ipv4_addr & 0xFF);
}

inline void ether_format_addr(char *buf, u_int16_t size,
                              const unsigned char* addr) {
    snprintf(buf, size, "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[0],
            addr[1],
            addr[2],
            addr[3],
            addr[4],
            addr[5]);
}

void ether_addr_dump(const char *what, const unsigned char* addr) {
    char buf[ETHER_ADDR_FMT_SIZE];
    
    ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, addr);
    if (what)
        printf("%s", what);
    printf("%s", buf);
}

void ipv4_addr_dump(const char *what, u_int32_t be_ipv4_addr) {
    char buf[16];
    
    ipv4_addr_to_dot(be_ipv4_addr, buf);
    if (what)
        printf("%s", what);
    printf("%s", buf);
}

static inline u_int16_t
ipv4_hdr_cksum(struct iphdr *ip_h)
{
	u_int16_t *v16_h;
	u_int32_t ip_cksum;

	/*
	 * Compute the sum of successive 16-bit words of the IPv4 header,
	 * skipping the checksum field of the header.
	 */
	v16_h = (u_int16_t *) ip_h;
	ip_cksum = v16_h[0] + v16_h[1] + v16_h[2] + v16_h[3] +
		v16_h[4] + v16_h[6] + v16_h[7] + v16_h[8] + v16_h[9];

	/* reduce 32 bit checksum to 16 bits and complement it */
	ip_cksum = (ip_cksum & 0xffff) + (ip_cksum >> 16);
	ip_cksum = (ip_cksum & 0xffff) + (ip_cksum >> 16);
	ip_cksum = (~ip_cksum) & 0x0000FFFF;
	return (ip_cksum == 0) ? 0xFFFF : (u_int16_t) ip_cksum;
}

#define is_multicast_ipv4_addr(ipv4_addr) \
	(((ntohl((ipv4_addr)) >> 24) & 0x000000FF) == 0xE0)

/*校验和算法*/
unsigned short cal_chksum(unsigned short *addr,int len)
{       int nleft=len;
        int sum=0;
        unsigned short *w=addr;
        unsigned short answer=0;

/*把ICMP报头二进制数据以2字节为单位累加起来*/
        while(nleft>1)
        {       sum+=*w++;
                nleft-=2;
        }
        /*若ICMP报头为奇数个字节，会剩下最后一字节。把最后一个字节视为一个2字节数据的高字节，这个2字节数据的低字节为0，继续累加*/
        if( nleft==1)
        {       *(unsigned char *)(&answer)=*(unsigned char *)w;
                sum+=answer;
        }
        sum=(sum>>16)+(sum&0xffff);
        sum+=(sum>>16);
        answer=~sum;
        return answer;
}

void build_arp_echo_xmit(u_int32_t dest_ip) {
	u_int8_t tx_buff[MIN_BUFFER_LEN];
	u_int8_t broadcast_mac[ETH_LEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

	/*
		* Build ARP echo.
		*/
	 struct ethhdr *eth_echo_h = (struct ethhdr *) tx_buff;
	 struct arphdr	*arp_echo_h = (struct arphdr *)(eth_echo_h + 1);
	 unsigned char *arp_echo_ptr = (unsigned char *)(arp_echo_h + 1);
	 
	 /* Use source MAC address as destination MAC address. */
	 memcpy(eth_echo_h->h_dest, broadcast_mac, ETH_LEN); 				 
	 /* Set source MAC address with MAC address of TX port */
	 memcpy(eth_echo_h->h_source, nic_mac, ETH_LEN);
	 eth_echo_h->h_proto = htons(ETH_P_ARP);
	 arp_echo_h->ar_hrd = htons(ARPHRD_ETHER);
	 arp_echo_h->ar_pro = htons(ETH_P_IP);
	 arp_echo_h->ar_hln = 6;
	 arp_echo_h->ar_pln = 4;
	 arp_echo_h->ar_op = htons(ARPOP_REQUEST);
	 memcpy(arp_echo_ptr, nic_mac, ETH_LEN);
	 arp_echo_ptr += ETH_LEN;
	 memcpy(arp_echo_ptr, &nic_ip, 4);
	 arp_echo_ptr += 4;
	 memcpy(arp_echo_ptr, broadcast_mac, ETH_LEN);
	 arp_echo_ptr += ETH_LEN;
	 memcpy(arp_echo_ptr, &dest_ip, 4);

	 packet_xmit(tx_buff, sizeof(struct ethhdr) + sizeof(struct arphdr) + 20);
}

/*
 * Receive a burst of packets, lookup for ICMP echo requests or ICMP response, and, if any,
 * send back ICMP echo replies.
 */
void arp_icmp_process(pfring_zc_pkt_buff *buffer) {
    struct ethhdr *eth_h;
    struct vlan_hdr *vlan_h;
    struct arphdr  *arp_h;
    struct iphdr *ip_h;
    struct icmphdr *icmp_h;
    unsigned char *arp_ptr;
    unsigned char *sha, *tha;
    u_int32_t sip, tip;
    u_int16_t eth_type;
    u_int16_t vlan_id;
    u_int16_t arp_op;
    u_int16_t arp_pro;
    int l2_len, i;
    u_char *pkt_data = pfring_zc_pkt_buff_data(buffer, zq_rx);
    u_int8_t tx_buff[MIN_BUFFER_LEN];
    
#ifdef DEBUG
    if (buffer->ts.tv_nsec)
        printf("[%u.%u] [hash=%08X]\n", buffer->ts.tv_sec, buffer->ts.tv_nsec, buffer->hash);
    
    for(i = 0; i < buffer->len; i++)
        printf("%02X ", pkt_data[i]);
    printf("\n");
#endif
    
    eth_h = (struct ethhdr *) pkt_data;
    eth_type = ntohs(eth_h->h_proto);
    l2_len = sizeof(struct ethhdr);
    
#ifdef DEBUG
    ether_addr_dump("  ETH:  src=", eth_h->h_source);
    ether_addr_dump(" dst=", eth_h->h_dest);
#endif
    
    if (eth_type == ETH_P_8021Q) {
        vlan_h = (struct vlan_hdr *)
                ((char *)eth_h + sizeof(struct ethhdr));
        l2_len	+= sizeof(struct vlan_hdr);
        eth_type = ntohs(vlan_h->h_vlan_encapsulated_proto);
        
#ifdef DEBUG
        vlan_id = ntohs(vlan_h->h_vlan_TCI)
                & 0xFFF;
        printf(" [vlan id=%u]", vlan_id);
#endif
    }
    
#ifdef DEBUG
    printf(" type=0x%04x\n", eth_type);
#endif
    
    /* Reply to ARP requests */
    if (eth_type == ETH_P_ARP) {
        arp_h = (struct arphdr *) ((char *)eth_h + l2_len);
        arp_op = ntohs(arp_h->ar_op);
        arp_pro = ntohs(arp_h->ar_pro);
        
#ifdef DEBUG
        printf("	ARP:	hrd=%d proto=0x%04x hln=%d "
               "pln=%d op=%u (%s)\n",
               ntohs(arp_h->ar_hrd),
               arp_pro, arp_h->ar_hln,
               arp_h->ar_pln, arp_op,
               arp_op_name(arp_op));
#endif
        
        if ((ntohs(arp_h->ar_hrd) !=
             ARPHRD_ETHER) ||
                (arp_pro != ETH_P_IP) ||
                (arp_h->ar_hln != 6) ||
                (arp_h->ar_pln != 4)
                ) {
#ifdef DEBUG
            printf("\n");
#endif
            
            return;
        }
        
        /*
         *	Extract fields
         */
        arp_ptr = (unsigned char *)(arp_h + 1);
        sha	= arp_ptr;
        arp_ptr += ETH_LEN;
        memcpy(&sip, arp_ptr, 4);
        arp_ptr += 4;
        tha	= arp_ptr;
        arp_ptr += ETH_LEN;
        memcpy(&tip, arp_ptr, 4);
        
#ifdef DEBUG
        ether_addr_dump(" 			 sha=", sha);
        ipv4_addr_dump(" sip=", sip);
        printf("\n");
        ether_addr_dump(" 			 tha=", tha);
        ipv4_addr_dump(" tip=", tip);
        printf("\n");
#endif
        
        if (arp_op == ARPOP_REQUEST && tip == nic_ip) {
            /*
             * Build ARP reply.
             */
            struct ethhdr *eth_reply_h = (struct ethhdr *) tx_buff;
            struct arphdr  *arp_reply_h = (struct arphdr *)(eth_reply_h + 1);
            unsigned char *arp_reply_ptr = (unsigned char *)(arp_reply_h + 1);
            
            /* Use source MAC address as destination MAC address. */
            memcpy(eth_reply_h->h_dest, eth_h->h_source, ETH_LEN);					
            /* Set source MAC address with MAC address of TX port */
            memcpy(eth_reply_h->h_source, nic_mac, ETH_LEN);
            eth_reply_h->h_proto = htons(ETH_P_ARP);
            arp_reply_h->ar_hrd = htons(ARPHRD_ETHER);
            arp_reply_h->ar_pro = htons(ETH_P_IP);
            arp_reply_h->ar_hln = 6;
            arp_reply_h->ar_pln = 4;
            arp_reply_h->ar_op = htons(ARPOP_REPLY);
            memcpy(arp_reply_ptr, nic_mac, ETH_LEN);
            arp_reply_ptr += ETH_LEN;
            memcpy(arp_reply_ptr, &nic_ip, 4);
            arp_reply_ptr += 4;
            memcpy(arp_reply_ptr, sha, ETH_LEN);
            arp_reply_ptr += ETH_LEN;
            memcpy(arp_reply_ptr, &sip, 4);

            packet_xmit(tx_buff, sizeof(struct ethhdr) + sizeof(struct arphdr) + 20);

            return;
        } else if(arp_op == ARPOP_REPLY && tip == nic_ip) {
            /*
             * Get reply mac and ip entry.
             */
            memcpy(dst_mac, sha, ETH_LEN);
#ifdef DEBUG
            ether_addr_dump(" 			 dst_mac=", dst_mac);
#endif            
            return;
        }
    }
    
    if (eth_type != ETH_P_IP) {
        return;
    }
    ip_h = (struct iphdr *) ((char *)eth_h + l2_len);
    
#ifdef DEBUG
    ipv4_addr_dump("	IPV4: src=", ip_h->saddr);
    ipv4_addr_dump(" dst=", ip_h->daddr);
    printf(" proto=%d (%s)\n",
           ip_h->protocol,
           ip_proto_name(ip_h->protocol));
#endif
    
    /*
     * Check if packet is a ICMP echo request.
     */
    icmp_h = (struct icmphdr *) ((char *)ip_h +
                                  sizeof(struct iphdr));
    if (! ((ip_h->protocol == IPPROTO_ICMP) &&
           (icmp_h->type == ICMP_ECHO) &&
           (icmp_h->code == 0))) {
        return;
    }
    
#ifdef DEBUG
    printf("	ICMP: echo request seq id=%d\n",
           ntohs(icmp_h->un.echo.sequence));
#endif
    
	{
	    /*
	     * Prepare ICMP echo reply to be sent back.
	     * - switch ethernet source and destinations addresses,
	     * - use the request IP source address as the reply IP
	     *		destination address,
	     * - if the request IP destination address is a multicast
	     *	 address:
	     *		 - choose a reply IP source address different from the
	     *			 request IP source address,
	     *		 - re-compute the IP header checksum.
	     *	 Otherwise:
	     *		 - switch the request IP source and destination
	     *			 addresses in the reply IP header,
	     *		 - keep the IP header checksum unchanged.
	     * - set IP_ICMP_ECHO_REPLY in ICMP header.
	     * ICMP checksum is computed by assuming it is valid in the
	     * echo request and not verified.
	     */
		  u_int16_t ip_totol_len = ntohs(ip_h->tot_len);
			struct ethhdr *eth_reply_h = (struct ethhdr *) tx_buff;;
			struct iphdr *ip_reply_h = (struct iphdr *)(eth_reply_h + 1);	
			struct icmphdr *icmp_reply_h = (struct icmphdr *)(ip_reply_h + 1);
			u_int32_t ip_addr;
     
			/* Use source MAC address as destination MAC address. */
			memcpy(eth_reply_h->h_dest, eth_h->h_source, ETH_LEN);					
			/* Set source MAC address with MAC address of TX port */
			memcpy(eth_reply_h->h_source, nic_mac, ETH_LEN);
			eth_reply_h->h_proto = htons(ETH_P_IP);

			memcpy((void*)ip_reply_h, (void*)ip_h, ip_totol_len);
	    ip_addr = ip_h->saddr;

	    if (is_multicast_ipv4_addr(ip_h->daddr)) {
	        u_int32_t ip_src;
	        
	        ip_src = ntohl(ip_addr);
	        if ((ip_src & 0x00000003) == 1)
	            ip_src = (ip_src & 0xFFFFFFFC) | 0x00000002;
	        else
	            ip_src = (ip_src & 0xFFFFFFFC) | 0x00000001;
	        ip_reply_h->saddr = htonl(ip_src);
	        ip_reply_h->daddr = ip_addr;
	    } else {
	        ip_reply_h->saddr = ip_h->daddr;
	        ip_reply_h->daddr = ip_addr;
	    }
			ip_reply_h->check = ipv4_hdr_cksum(ip_reply_h);
			
	    icmp_reply_h->type = ICMP_ECHOREPLY;
	    icmp_reply_h->checksum = 0;
			memcpy((void*)icmp_reply_h+sizeof(struct icmphdr), (void*)icmp_h+sizeof(struct icmphdr), 8);
	    icmp_reply_h->checksum = cal_chksum((u_short*)icmp_reply_h, ip_totol_len - ip_h->ihl*4);

#ifdef DEBUG
			printf("Send icmp reply\n");
			int len = sizeof(struct ethhdr) + ip_totol_len;
			for(i = 0; i < len; i++)
					printf("%02X ", tx_buff[i]);
			printf("\n");

#endif
			packet_xmit(tx_buff, sizeof(struct ethhdr) + ip_totol_len);
	}
}


