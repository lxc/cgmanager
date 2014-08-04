EXTRA_DIST = cgmanager.service cgproxy.service

if INIT_SCRIPT_SYSTEMD
SYSTEMD_UNIT_DIR = $(prefix)/lib/systemd/system

install-systemd: cgmanager.service cgproxy.service
	$(MKDIR_P) $(DESTDIR)$(SYSTEMD_UNIT_DIR)
	$(INSTALL_DATA) cgmanager.service $(DESTDIR)$(SYSTEMD_UNIT_DIR)/
	$(INSTALL_DATA) cgproxy.service $(DESTDIR)$(SYSTEMD_UNIT_DIR)/

uninstall-systemd:
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/cgmanager.service
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/cgroxy.service
	rmdir $(DESTDIR)$(SYSTEMD_UNIT_DIR) || :

install-data-local: install-systemd
uninstall-local: uninstall-systemd
endif
