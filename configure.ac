# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([cgmanager], [0.02], [cgmanager-devel@lists.linuxcontainers.org])

AC_GNU_SOURCE
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile libcgmanager.pc.in])

AM_INIT_AUTOMAKE

LT_INIT
AC_PROG_CC

AC_PATH_PROG([NIH_DBUS_TOOL], [nih-dbus-tool])

PKG_CHECK_MODULES([NIH], [libnih >= 1.0.2])
PKG_CHECK_MODULES([NIH_DBUS], [libnih-dbus >= 1.0.0])
PKG_CHECK_MODULES([DBUS], [dbus-1 >= 1.2.16])

AC_OUTPUT
