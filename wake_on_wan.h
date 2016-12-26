#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
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

struct packet_data {

	uint8_t dst_inet_addr [IP_ALEN];
	uint8_t src_inet_addr [IP_ALEN];
	uint8_t dst_hw_addr [ETH_ALEN];
	uint8_t src_hw_addr [ETH_ALEN];
	uint8_t wow_hw_addr [ETH_ALEN];
	uint16_t dst_port;
	uint16_t src_port;
};

int create_wow_packet( struct packet_data *pd, char *interface, uint8_t *packet );

char *find_network_interface();

int get_phy_addr( char *interface, uint8_t *hwaddr, uint8_t *ipaddr );

int parse_host_file( struct packet_data *pd );

int get_last_hf( char *conf_file, char *filename );
