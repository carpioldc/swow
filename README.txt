This is UNDER CONSTRUCTION (maybe)

_______________________________________________________________________________

	So, how to make it work: 

1.	Open port 9 on router (if you didn't already)

2.	Make sure your arp table contains route to the remote host

3.	By now you'll need change the addresses on wake_on_wan.c at the 
	function "parse_host_file". 

4.	Remember to activate magic packet wol at your remote machine. You can
	do this by running

		 [remote@host ~]$ sudo ethtool -s eth0 wol g
	
	Note that you may need to do this at every power-off
_______________________________________________________________________________

