ACLOCAL_AMFLAGS = -I m4

VERSION_CURRENT  = 0
VERSION_REVISION = 0
VERSION_AGE      = 0

LIBCGMANAGER_VERSION        = $(VERSION_CURRENT):$(VERSION_REVISION):$(VERSION_AGE)
LIBCGMANAGER_VERSION_DOTTED = $(VERSION_CURRENT).$(VERSION_REVISION).$(VERSION_AGE)

AM_CFLAGS = -Wall -ggdb -D_GNU_SOURCE
AM_CFLAGS += $(DBUS_CFLAGS) $(NIH_CFLAGS) $(NIH_DBUS_CFLAGS)
AM_LDFLAGS = $(DBUS_LIBS) $(NIH_LIBS) $(NIH_DBUS_LIBS)
client_files_OUTPUTS = cgmanager-client.c cgmanager-client.h
manager_files_OUTPUTS = org.linuxcontainers.cgmanager.c org.linuxcontainers.cgmanager.h

BUILT_SOURCES = $(manager_files_OUTPUTS) $(client_files_OUTPUTS)

CLEANFILES = \
	$(manager_files_OUTPUTS) \
	$(client_files_OUTPUTS) \
	getpidcgroup movepid cgmanager chowncgroup cgproxy \
	*.o *.so \
	libcgmanager.pc.in

sbin_PROGRAMS = cgmanager cgproxy
bin_PROGRAMS = movepid getpidcgroup chowncgroup
bin_SCRIPTS = runtests.sh

lib_LTLIBRARIES = libcgmanager.la

libcgmanager.pc: libcgmanager.pc.in
	sed -e 's|[@]LIBCGMANAGER_VERSION_DOTTED[@]|$(LIBCGMANAGER_VERSION_DOTTED)|g' \
		$< > $@

EXTRA_DIST = libcgmanager.pc.in.in 

pkgconfigdir = $(prefix)/lib/pkgconfig
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
	fs.c fs.h

cgproxy_SOURCES = cgmanager-proxy.c \
	$(manager_files_OUTPUTS) \
	access_checks.c access_checks.h \
	fs.c fs.h

getpidcgroup_SOURCES = getpidcgroup.c
chowncgroup_SOURCES = chowncgroup.c
movepid_SOURCES = movepid.c

libcgmanager_la_SOURCES = \
	$(client_files_OUTPUTS) \
	org.linuxcontainers.cgmanager.xml
libcgmanager_la_CFLAGS = -fPIC -DPIC $(DBUS_CFLAGS) $(NIH_CFLAGS) $(NIH_DBUS_CFLAGS)
libcgmanager_la_LDFLAGS = -E \
	-version-info $(LIBCGMANAGER_VERSION)
libcgmanager_la_LIBADD = \
	$(DBUS_LIBS) $(NIH_CFLAGS) $(NIH_DBUS_CFLAGS)
