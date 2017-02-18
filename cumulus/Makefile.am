
sbin_PROGRAMS = ssd
EXTRA_DIST = etc/quagga/debian.conf etc/quagga/daemons etc/default/quagga \
	     usr/share/cumulus/support/quagga

ssd_SOURCES = start-stop-daemon.c

install-data-local:
	mkdir -p mkdir -p $(DESTDIR)/usr/share/cumulus/support
	cp -a usr/share/cumulus/support/quagga $(DESTDIR)/usr/share/cumulus/support
