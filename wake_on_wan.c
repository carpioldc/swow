#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define ETH_MAX_LEN 1512
#define ETH_HLEN 14
#define IP_HLEN 20
#define UDP_HLEN 8
#define WOL_LEN 102
#define ETH_ALEN 6
#define IP_ALEN 4
#define UDP_PLEN 2

int create_wow_packet( const uint32_t ip_dest, const uint16_t port_dest, char *interface, uint8_t *packet );
char *find_network_interface();
int get_phy_addr( char *interface, uint8_t *hwaddr, uint8_t *ipaddr );

int main(int argc, char **argv) {

	/* Variables */
	uint16_t d_port;
	struct in_addr d_ip;
	char *use_str = "Usage: wow [port] ip_dest";
	const int p_len = ETH_HLEN + IP_HLEN + UDP_HLEN + WOL_LEN;
	uint8_t packet [p_len];
	
	/* Parse arguments */
	if (argc > 3 || argc < 1) {
		perror( use_str );
		exit( EXIT_FAILURE );
	}
	else {
		if (inet_aton(argv[argc-1], &d_ip) == 0) {
			perror( "Invalid address" );
			exit( EXIT_FAILURE );
		}
		
		if (argc == 3)
			d_port = (uint16_t)strtol( argv[1], NULL, 10 );
		else
			d_port = 9;
		d_port = htons( d_port );
	}	

	/* Welcome message */
	printf( "Wake on WAN version 1.0\nCreated by Jorge Carpio\n");	
	/* Open pcap session */
	int to_ms = 1000;
	char *device = find_network_interface();
	printf( "Opening pcap session on [%s]\n", device );
	char errbuff[PCAP_ERRBUF_SIZE];
	pcap_t *p = pcap_open_live( device, ETH_MAX_LEN, 0, to_ms, errbuff );
	if( p == NULL ) {
		printf( "Error opening live capture\n%s\n", errbuff);
		return EXIT_FAILURE;
	}
		
	/* Packetize */
	
	if(create_wow_packet( d_ip.s_addr, d_port, device, packet )) {
		perror( "Error creating the packet" );
		exit( EXIT_FAILURE );

	}
	
	/* Send packet*/        
	pcap_inject( p, packet, p_len );

	printf( "IP: %x ", d_ip.s_addr );
	printf("%s\n", inet_ntoa(d_ip));
	printf( "Port: %x\n", d_port );
	
	printf( "Packet: ");
	for (int i = 0; i < p_len; i++ ) {
		printf( "%x ", packet[i]);
	}
	printf( "\n" );
	
	/* Close pcap and exit */
	pcap_close( p );
	return EXIT_SUCCESS;
}


int create_wow_packet( uint32_t ip_dest, uint16_t port_dest, char* interface, uint8_t *packet ) {
	
	uint8_t *ptr = packet;
	uint16_t port_source = 4000;
	uint8_t ip_source [IP_ALEN];
	uint8_t phy_source [ETH_ALEN];
	uint8_t phy_broad [ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	uint8_t phy_dest [ETH_ALEN] = {0x00, 0x0a, 0xe6, 0x1a, 0xdb, 0xb2};
	uint16_t ethertype = htons(0x0800);

	if( get_phy_addr( interface, phy_source, ip_source ) != 0 )
		return EXIT_FAILURE;

	/* Ethernet header */
	memcpy( ptr, phy_broad, ETH_ALEN );
	ptr += ETH_ALEN;
	memcpy( ptr, phy_source, ETH_ALEN );
	ptr += ETH_ALEN;
	memcpy( ptr, &ethertype, 2 );
	ptr += 2;

	/* IP header */
	uint8_t fields [12] = {0x45, 0x00, 0x00, 0x82, 0x1f, 0x0d, 0x40, 0x00, 0x40, 0x11, 0xff, 0xff}; // FIX CHECKSUM;
	memcpy( ptr, fields, 12 );
	ptr += 12;
	 
	for (int j = 1; j <= IP_ALEN; j ++)
		ptr[IP_ALEN - j] = ip_source[j-1];
	
	ptr += IP_ALEN;
	memcpy( ptr, &ip_dest, IP_ALEN );
	ptr += IP_ALEN;

	/* UDP header */
	memcpy( ptr, &port_source, UDP_PLEN );
	ptr += UDP_PLEN;
	memcpy( ptr, &port_dest, UDP_PLEN );
	ptr += UDP_PLEN;
	fields[0] = 0x00;
       	fields[1] = 0x6e;
       	fields[2] = 0xff;
	fields[3] = 0xff; // FIX CHECKSUM
	memcpy( ptr, fields, 4 );
	ptr += 4;
	
	/* WOW content*/
	uint8_t sync [ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	memcpy( ptr, sync, ETH_ALEN );
	ptr += ETH_ALEN;
	for (int k = 0; k < 16; k ++) {
		memcpy( ptr, phy_dest, ETH_ALEN );
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

	for( int r = 0; r < ifc.ifc_len; r ++) {
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

