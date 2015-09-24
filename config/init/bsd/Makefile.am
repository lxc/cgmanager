EXTRA_DIST = rc.cgmanager rc.cgproxy

if INIT_SCRIPT_BSD
install-bsd: rc.cgmanager rc.cgproxy
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/rc.d
	$(INSTALL_SCRIPT) rc.cgmanager $(DESTDIR)$(sysconfdir)/rc.d/rc.cgmanager
	$(INSTALL_SCRIPT) rc.cgproxy $(DESTDIR)$(sysconfdir)/rc.d/rc.cgproxy

uninstall-bsd:
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/rc.cgmanager
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/rc.cgproxy
	rmdir $(DESTDIR)$(sysconfdir)/rc.d || :

install-data-local: install-bsd
uninstall-local: uninstall-bsd
endif
