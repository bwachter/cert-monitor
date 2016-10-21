DBUS_LIBS=$(shell pkg-config --libs dbus-1)
DBUS_CFLAGS=$(shell pkg-config --cflags dbus-1)
SYSTEMD_LIBS=$(shell pkg-config --libs libsystemd-journal)
SYSTEMD_CFLAGS=$(shell pkg-config --cflags libsystemd-journal)

.PHONY: clean

cert-monitor: cert-monitor.c
	gcc -Wall -Werror -o $@ $(SYSTEMD_LIBS) $(SYSTEMD_CFLAGS) $(DBUS_LIBS) $(DBUS_CFLAGS) -ldbus-1 $<

clean:
	rm -f cert-monitor *.o
