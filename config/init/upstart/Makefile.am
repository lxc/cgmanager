EXTRA_DIST = cgmanager.conf cgproxy.conf

if INIT_SCRIPT_UPSTART
install-upstart: cgmanager.conf cgproxy.conf
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/init/
	$(INSTALL_DATA) cgmanager.conf $(DESTDIR)$(sysconfdir)/init/
	$(INSTALL_DATA) cgproxy.conf $(DESTDIR)$(sysconfdir)/init/

uninstall-upstart:
	rm -f $(DESTDIR)$(sysconfdir)/init/cgmanager.conf
	rm -f $(DESTDIR)$(sysconfdir)/init/cgproxy.conf
	rmdir $(DESTDIR)$(sysconfdir)/init || :

install-data-local: install-upstart
uninstall-local: uninstall-upstart
endif

SUBDIRS = sessions
