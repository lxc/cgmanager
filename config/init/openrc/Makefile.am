EXTRA_DIST = cgmanager cgproxy

if INIT_SCRIPT_OPENRC
RC_INIT_DIR = $(sysconfdir)/init.d

install-openrc: cgmanager cgproxy
	$(MKDIR_P) $(DESTDIR)$(RC_INIT_DIR)
	$(INSTALL_DATA) cgmanager $(DESTDIR)$(RC_INIT_DIR)/
	$(INSTALL_DATA) cgproxy $(DESTDIR)$(RC_INIT_DIR)/

uninstall-openrc:
	rm -f $(DESTDIR)$(RC_INIT_DIR)/cgmanager
	rm -f $(DESTDIR)$(RC_INIT_DIR)/cgroxy
	rmdir $(DESTDIR)$(RC_INIT_DIR) || :

install-data-local: install-openrc
uninstall-local: uninstall-openrc
endif
