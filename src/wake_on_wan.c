#include "rc_funcs.h"
#include "wake_on_wan.h"

/**
 * Wake on WAN
 *
 *
 */
int main(int argc, char **argv) {

	/* Variables */
	struct in_addr d_ip;
	struct packet_data pd;
	const int p_len = ETH_HLEN + IP_HLEN + UDP_HLEN + WOL_LEN;
	uint8_t packet [p_len];
	char* host_file = NULL;	
	char* conf = "/etc/wowan/wowlan.conf";
	int c;	
	
	/* Parse arguments */
	while((c = getopt (argc, argv, "c:")) != -1)
		switch (c)
		{
			case 'c':
				host_file = optarg;
				break;
			case '?':
				if (optopt == 'c')
					fprintf (stderr, "Option -%c requires to specify the host file as argument.\n", optopt);
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr, "Unknown option character `\\x%x'.\n",	optopt);
				return EXIT_FAILURE;
			default:
				abort ();
		}

	if( host_file == NULL )
		get_last_hf( conf, host_file );
		
	parse_host_file( &pd, host_file );
			
	/* Welcome message */
	printf( "Wake On WAN version 1.0\n" );
	
	/* Open pcap session */
	int to_ms = 1000;
	char *device = find_network_interface();
	char errbuff[PCAP_ERRBUF_SIZE];
	
	printf( "Opening pcap session on [%s]\n", device );
	pcap_t *p = pcap_open_live( device, ETH_MAX_LEN, 0, to_ms, errbuff );
	if( p == NULL ) {
		printf( "Error opening live capture\n%s\n", errbuff);
		return EXIT_FAILURE;
	}
		
	/* Packetize */
	
	if(create_wow_packet( &pd, device, packet )) {
		perror( "Error creating the packet" );
		exit( EXIT_FAILURE );

	}
	
	/* Send packet*/        
	pcap_inject( p, packet, p_len );
	printf( "Magic packet sent succesfully!\n" );
	
	/* Close pcap and exit */
	pcap_close( p );
	return EXIT_SUCCESS;
}


int create_wow_packet( struct packet_data *pd, char* interface, uint8_t *packet ) {
	
	uint8_t *ptr = packet;
	uint8_t brd_hw_addr [ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	uint16_t ethertype = htons(0x0800);
	uint16_t crc;
	
	/* Ethernet header */
	memcpy( ptr, &pd->dst_hw_addr, ETH_ALEN );
	ptr += ETH_ALEN;
	memcpy( ptr, &pd->src_hw_addr, ETH_ALEN );
	ptr += ETH_ALEN;
	memcpy( ptr, &ethertype, 2 );
	ptr += 2;

	/* IP header */
	uint8_t fields [10] = {0x45, 0x00, 0x00, 0x82, 0x1f, 0x0d, 0x40, 0x00, 0x40, 0x11};
	memcpy( ptr, fields, 10 );
	ptr += 10;
	
	crc = crc_ccitt( fields, 10 ); /* IP checksum */
	//crc = htons( crc );
	crc = 0x3623;
	memcpy( ptr, &crc, 2 );
        ptr += 2;

	/* for (int j = 1; j <= IP_ALEN; j ++)
	 *	ptr[IP_ALEN - j] = pd->src_inet_addr[j-1];
	 */

	memcpy( ptr, pd->src_inet_addr, IP_ALEN );
	ptr += IP_ALEN;
	memcpy( ptr, pd->dst_inet_addr, IP_ALEN );
	ptr += IP_ALEN;

	/* UDP header */
	memcpy( ptr, &pd->src_port, UDP_PLEN );
	ptr += UDP_PLEN;
	memcpy( ptr, &pd->dst_port, UDP_PLEN );
	ptr += UDP_PLEN;
	fields[0] = 0x00;
       	fields[1] = 0x6e;
       	fields[2] = 0x00;	/* UDP checksum not used */
       	fields[3] = 0x00;
	memcpy( ptr, fields, 4 );
	ptr += 4;
	
	/* WOW content*/
	uint8_t *sync = brd_hw_addr;
	memcpy( ptr, sync, ETH_ALEN );
	ptr += ETH_ALEN;
  int k = 0;
	for (k; k < 16; k ++) {
		memcpy( ptr, pd->wow_hw_addr, ETH_ALEN );
		ptr += ETH_ALEN;
	}
	
	return 0;
}

char *find_network_interface() {

	char *device; /* Name of device (e.g. eth0, wlan0) */
	char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */

	/* Find a device */
	device = pcap_lookupdev(error_buffer);
	if (device == NULL) {
		printf("Error finding device: %s\n", error_buffer);
		return NULL;
	}
	else
		return device;
}


int get_phy_addr( char *interface, uint8_t *hwaddr, uint8_t *ipaddr ) {

	int s;
	struct ifreq ifr;
	struct ifconf ifc;
	ifc.ifc_req = &ifr;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(ifr.ifr_name, interface);
	if(ioctl(s, SIOCGIFHWADDR, &ifr) == -1)
		return EXIT_FAILURE;

	memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	memcpy(ipaddr, ifr.ifr_addr.sa_data, IP_ALEN);
	
	if(ioctl(s, SIOCGIFCONF, &ifc) == -1)
		return EXIT_FAILURE;

	printf( "%d addresses returned\n", ifc.ifc_len);

  int r = 0;
	for (r; r < ifc.ifc_len; r ++) {
		memcpy(ipaddr, ifc.ifc_req[r].ifr_addr.sa_data, IP_ALEN);
		printf("%d:: %s %s ip: ", r, "Interface", ifc.ifc_req[r].ifr_name);
		printf("%d.", ipaddr[0]);
		printf("%d.", ipaddr[1]);
		printf("%d.", ipaddr[2]);
		printf("%d", ipaddr[3]);
		printf("\n");
	}
		
	return 0;
}

/**
 *
 */
int parse_host_file( struct packet_data *pd, char* filename ) {

	uint8_t dinetaddr[IP_ALEN] = {2, 139, 51, 209}; 
	uint8_t sinetaddr[IP_ALEN] = {192, 168, 1, 36};
	uint8_t dhwaddr[ETH_ALEN] = {0x38, 0x72, 0xc0, 0x35, 0x94, 0xd6};
	uint8_t shwaddr[ETH_ALEN] = {0xe8, 0x11, 0x32, 0xee, 0x8b, 0xc4};
	uint8_t whwaddr[ETH_ALEN] = {0x00, 0x0a, 0xe6, 0x1a, 0xdb, 0xb2};
	uint16_t dport = htons(9);
	uint16_t sport = htons(4000);

	memcpy( pd->dst_inet_addr, dinetaddr, IP_ALEN );
	memcpy( pd->src_inet_addr, sinetaddr, IP_ALEN ); 
	memcpy( pd->dst_hw_addr, dhwaddr, ETH_ALEN );
	memcpy( pd->src_hw_addr, shwaddr, ETH_ALEN );
	memcpy( pd->wow_hw_addr, whwaddr, ETH_ALEN );
	pd->dst_port = dport;
	pd->src_port = sport;
}

/**
 *
 */
int get_last_hf( char* conf_file, char* filename ) {

	FILE *fp;
	char **lineptr;
	size_t *n;
	*lineptr = NULL;
	*n = 0;

	fp = fopen(filename, "r");
	if( fp == NULL )
		return EXIT_FAILURE;

	while( getline( lineptr, n, fp ) != -1 ) {
		// AQUI determine last host file
	}
}

