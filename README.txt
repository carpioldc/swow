int pcap_inject(pcap_t *p, const void *buf, size_t size);

/*
 * Ethernet header:
 * 
 * source MAC: ff ff ff ff ff ff 
 * destin MAC: e8 11 32 ee 8b c4 
 * ethertype : 08 00 
 * 
 * IP header:
 *
 * header length: 45
 * diff. services field: 00 00 
 * total length: 82 
 * identification: 1f 0d 
 * flags: 40 (don't fragment)
 * fragment offset: 00 
 * time to live: 40 
 * protocol: 11 (udp)
 * header checksum: 59 89 
 * source IP: c0 a8 01 2d 
 * destin IP: ff ff ff ff 
 *
 * UDP:
 *
 * source port: dc 27 
 * destin port: 9c 40 
 * length: 00 6e
 * checksum: a7 58 
 *
 * Wake On LAN:
 *
 * sync stream: ff ff ff ff ff ff 
 * MAC: 00 0a e6 1a db b2 (x16 times) 
 * MAC: 00 0a e6 1a db b2 
 * [...]
 * MAC: 00 0a e6 1a db b2
  */

ffffffffffffe81132ee8bc40800

450000821f0d400040115989c0a8012dffffffff

dc279c40006ea758

ffffffffffff000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2

CHANGES:

/*
 * Ethernet header: none
 * 
 * 
 * IP header:
 *
 * destin IP: ff ff ff ff -> WAN IP given by user 
 *
 * UDP:
 *
 * destin port: -> router port given by user, default 9
 *
 * Wake On LAN: none
  */


Link layer: ffffffffffffe81132ee8bc40800

Network layer: 450000821f0d400040115989c0a8012????????

Transport layer: dc270009006ea758

Application layer: ffffffffffff000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2000ae61adbb2
