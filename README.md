# Wake on WAN

This is an effort to extend the Wake on LAN protocol to work from outside your LAN through port forwarding. You must note that last time I tried this was not exactly working.

## Steps to make it work:

### Build

Clone the repository. 

    $ git clone git@github.com:carpioldc/wowan.git

Build things. Requires libpcap.
    
    $ cd wowan
    $ make
    $ sudo make install

### Configure remote host and network

1.  Map the host to a static IP address. Update addresses on wake\_on\_wan.c at the parse\_host\_file function (work in progress here).

2.  Forward port 9 (WoL default) of the desired machine all the way out into the wilderness.

3.  Make sure the router's ARP knows how to route to the remote host.

4.  Remember to activate WoL (magic packet mode) on your sleepy machine interface. You can do this by running ``ethtool -s eth0 wol g`` as root. Make sure this change persists power-offs.


*Good luck.*

