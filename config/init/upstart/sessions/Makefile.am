EXTRA_DIST = cgmanager.conf

if INIT_SCRIPT_UPSTART
install-upstart-session: cgmanager.conf
	$(MKDIR_P) $(DESTDIR)${datadir}/upstart/sessions/
	$(INSTALL_DATA) cgmanager.conf $(DESTDIR)${datadir}/upstart/sessions/

uninstall-upstart-session:
	rm -f $(DESTDIR)${datadir}/upstart/sessions/cgmanager.conf
	rmdir $(DESTDIR)${datadir}/upstart/sessions || :

install-data-local: install-upstart-session
uninstall-local: uninstall-upstart-session
endif
