EXTRA_DIST = cgmanager cgproxy

if INIT_SCRIPT_SYSV
install-sysvinit: cgmanager cgproxy
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/rc.d/init.d
	$(INSTALL_SCRIPT) cgmanager $(DESTDIR)$(sysconfdir)/rc.d/init.d/cgmanager
	$(INSTALL_SCRIPT) cgproxy $(DESTDIR)$(sysconfdir)/rc.d/init.d/cgproxy

uninstall-sysvinit:
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/init.d/cgmanager
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/init.d/cgproxy
	rmdir $(DESTDIR)$(sysconfdir)/rc.d/init.d || :

install-data-local: install-sysvinit
uninstall-local: uninstall-sysvinit
endif
