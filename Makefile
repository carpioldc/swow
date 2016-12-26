all: wake_on_wan

wake_on_wan: wake_on_wan.c rc_funcs.c
	gcc -lpcap wake_on_wan.c rc_funcs.c -o wow

install: wow
	install -m 0755 wow /bin
