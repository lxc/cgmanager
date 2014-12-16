ACLOCAL_AMFLAGS = -I m4

VERSION_CURRENT  = 0
VERSION_REVISION = 0
VERSION_AGE      = 0

LIBCGMANAGER_VERSION        = $(VERSION_CURRENT):$(VERSION_REVISION):$(VERSION_AGE)
LIBCGMANAGER_VERSION_DOTTED = $(VERSION_CURRENT).$(VERSION_REVISION).$(VERSION_AGE)

AM_CFLAGS = -Wall -ggdb -D_GNU_SOURCE -DSBINDIR=\"$(SBINDIR)\"
AM_CFLAGS += $(DBUS_CFLAGS) $(NIH_CFLAGS) $(NIH_DBUS_CFLAGS)
AM_LDFLAGS = $(DBUS_LIBS) $(NIH_LIBS) $(NIH_DBUS_LIBS)
client_files_OUTPUTS = cgmanager-client.c cgmanager-client.h
manager_files_OUTPUTS = org.linuxcontainers.cgmanager.c org.linuxcontainers.cgmanager.h

BUILT_SOURCES = $(manager_files_OUTPUTS) $(client_files_OUTPUTS)

CLEANFILES = \
	$(manager_files_OUTPUTS) \
	$(client_files_OUTPUTS) \
	cgmanager cgproxy \
	cgm-release-agent  \
	*.o *.so \
	libcgmanager.pc.in

sbin_PROGRAMS = cgmanager cgproxy cgm-release-agent
bin_PROGRAMS = cgm

lib_LTLIBRARIES = libcgmanager.la

pkginclude_HEADERS = cgmanager-client.h cgmanager.h

if HAVE_HELP2MAN
man_MANS = cgm.1 cgproxy.8 cgmanager.8
endif

libcgmanager.pc: libcgmanager.pc.in
	sed -e 's|[@]LIBCGMANAGER_VERSION_DOTTED[@]|$(LIBCGMANAGER_VERSION_DOTTED)|g' \
		$< > $@

EXTRA_DIST = libcgmanager.pc.in.in cgmanager.spec cgm cgm.man.add \
	cgmanager.man.add cgproxy.man.add tests/*.sh tests/*.c

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcgmanager.pc

$(manager_files_OUTPUTS): org.linuxcontainers.cgmanager.xml
	$(AM_V_GEN)$(NIH_DBUS_TOOL) \
	--package=cgmanager \
	--mode=object \
	--prefix=cgmanager \
	--default-interface=org.linuxcontainers.cgmanager0_0 \
	org.linuxcontainers.cgmanager.xml

$(client_files_OUTPUTS): org.linuxcontainers.cgmanager.xml
	$(AM_V_GEN)$(NIH_DBUS_TOOL) \
	--package=cgmanager \
	--mode=proxy --prefix=cgmanager \
	--default-interface=org.linuxcontainers.cgmanager0_0 \
	--output=cgmanager-client.c \
	org.linuxcontainers.cgmanager.xml

cgmanager_SOURCES = cgmanager.c \
	$(manager_files_OUTPUTS) \
	access_checks.h access_checks.c \
	fs.c fs.h cgmanager.h \
	frontend.c frontend.h

cgmanager_CFLAGS = $(AM_CFLAGS) -DCGMANAGER

cgproxy_SOURCES = cgmanager-proxy.c \
	$(manager_files_OUTPUTS) \
	access_checks.c access_checks.h \
	fs.c fs.h cgmanager.h \
	frontend.c frontend.h

cgm_release_agent_SOURCES = cgm-release-agent.c
cgm_release_agent_LDADD = -L.libs -lcgmanager
cgm_release_agent_DEPENDENCIES = libcgmanager.la

cgm_SOURCES = cgm.c cgmanager.h
cgm_LDADD = -L.libs -lcgmanager
cgm_DEPENDENCIES = libcgmanager.la

libcgmanager_la_SOURCES = \
	$(client_files_OUTPUTS) \
	org.linuxcontainers.cgmanager.xml
libcgmanager_la_CFLAGS = -fPIC -DPIC $(DBUS_CFLAGS) $(NIH_CFLAGS) $(NIH_DBUS_CFLAGS)
libcgmanager_la_LDFLAGS = -E \
	-version-info $(LIBCGMANAGER_VERSION)
libcgmanager_la_LIBADD = \
	$(DBUS_LIBS) $(NIH_LIBS) $(NIH_DBUS_LIBS)

if HAVE_HELP2MAN
cgmanager.8: cgmanager.c cgmanager cgmanager.man.add
	$(HELP2MAN) -n "a daemon to manage cgroups" -s 8 -I cgmanager.man.add -N ./cgmanager > cgmanager.8

cgproxy.8: cgmanager-proxy.c cgproxy cgproxy.man.add
	$(HELP2MAN) -n "a proxy for cgmanager" -s 8 -I cgproxy.man.add -N ./cgproxy > cgproxy.8

cgm.1: cgm cgm.man.add
	$(HELP2MAN) -n "a client script for cgmanager" -s 1 -I cgm.man.add -N ./cgm > cgm.1
endif

install-exec-local:
	$(MKDIR_P) $(DESTDIR)/usr/share/cgmanager/tests
	cd tests; \
	for f in *.sh; do \
	install -c -m 755 $$f $(DESTDIR)/usr/share/cgmanager/tests; \
	done

rpm: dist
	rpmbuild --clean -ta ${distdir}.tar.gz

TESTS_SCM: tests/scmtest.c
	$(CC) -o tests/scmtest tests/scmtest.c

tests/nstest.o: tests/nstest.c
	$(CC) -I. $(NIH_CFLAGS) $(NIH_DBUS_CFLAGS) $(DBUS_CFLAGS)  -c \
		-fPIC -DPIC -o tests/nstest.o tests/nstest.c

TEST_NSTEST: tests/nstest.o
	$(CCLD) -o tests/nstest tests/nstest.o \
		$(NIH_LIBS) $(NIH_DBUS_LIBS) $(DBUS_LIBS) -lcgmanager

tests/cgm-concurrent.o: tests/cgm-concurrent.c
	$(CC) -I. $(NIH_CFLAGS) $(NIH_DBUS_CFLAGS) $(DBUS_CFLAGS)  -c \
		-fPIC -DPIC -o tests/cgm-concurrent.o tests/cgm-concurrent.c

TESTS_CGM_CONCURRENT: tests/cgm-concurrent.o
	$(CCLD) -o tests/cgm-concurrent tests/cgm-concurrent.o \
		$(NIH_LIBS) $(NIH_DBUS_LIBS) $(DBUS_LIBS) -lpthread -lcgmanager

tests: TESTS_CGM_CONCURRENT TESTS_SCM TEST_NSTEST

SUBDIRS = config
