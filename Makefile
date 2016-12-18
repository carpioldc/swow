all: wake_on_wan

wake_on_wan: wake_on_wan.c
	gcc -lpcap wake_on_wan.c -o wow
