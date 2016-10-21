DBUS_LIBS=$(shell pkg-config --libs dbus-1)
DBUS_CFLAGS=$(shell pkg-config --cflags dbus-1)
SYSTEMD_LIBS=$(shell pkg-config --libs libsystemd-journal)
SYSTEMD_CFLAGS=$(shell pkg-config --cflags libsystemd-journal)

BINDIR?=/usr/bin
UNITDIR?=/usr/lib/systemd/system

.PHONY: clean

cert-monitor: cert-monitor.c
	gcc -Wall -Werror $< -o $@ $(SYSTEMD_LIBS) $(SYSTEMD_CFLAGS) $(DBUS_LIBS) $(DBUS_CFLAGS) -ldbus-1

install: cert-monitor
	install -D -m755 cert-monitor $(DESTDIR)/$(BINDIR)/cert-monitor
	install -D -m644 cert-monitor.service $(DESTDIR)/$(UNITDIR)/cert-monitor.service

clean:
	rm -f cert-monitor *.o
