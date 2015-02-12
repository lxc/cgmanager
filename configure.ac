# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([cgmanager], [0.36], [cgmanager-devel@lists.linuxcontainers.org])

AC_GNU_SOURCE
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
	config/Makefile
	config/init/Makefile
	config/init/systemd/Makefile
	config/init/sysvinit/Makefile
	config/init/upstart/Makefile
	config/init/upstart/sessions/Makefile
	libcgmanager.pc.in
	cgmanager.spec])

AM_INIT_AUTOMAKE

LT_INIT
AC_PROG_CC

AC_PROG_CC_C99

AC_PATH_PROG([NIH_DBUS_TOOL], [nih-dbus-tool])

AC_CHECK_FUNCS([setns pivot_root])

PKG_CHECK_MODULES([NIH], [libnih >= 1.0.3])
PKG_CHECK_MODULES([NIH_DBUS], [libnih-dbus >= 1.0.0])
PKG_CHECK_MODULES([DBUS], [dbus-1 >= 1.2.16])

# Detect the distribution. This is used for the default configuration and
# for some distro-specific build options.
AC_MSG_CHECKING([host distribution])
AC_ARG_WITH(distro, AS_HELP_STRING([--with-distro=DISTRO], [Specify the Linux distribution to target: One of redhat, oracle, centos, fedora, suse, gentoo, debian, arch, slackware, paldo, openmandriva or pardus.]))
if type lsb_release >/dev/null 2>&1 && test "z$with_distro" = "z"; then
	with_distro=`lsb_release -is`
fi
if test "z$with_distro" = "z"; then
	AC_CHECK_FILE(/etc/redhat-release,with_distro="redhat")
	AC_CHECK_FILE(/etc/oracle-release,with_distro="oracle")
	AC_CHECK_FILE(/etc/centos-release,with_distro="centos")
	AC_CHECK_FILE(/etc/fedora-release,with_distro="fedora")
	AC_CHECK_FILE(/etc/SuSE-release,with_distro="suse")
	AC_CHECK_FILE(/etc/gentoo-release,with_distro="gentoo")
	AC_CHECK_FILE(/etc/debian_version,with_distro="debian")
	AC_CHECK_FILE(/etc/arch-release,with_distro="arch")
	AC_CHECK_FILE(/etc/slackware-version,with_distro="slackware")
	AC_CHECK_FILE(/etc/frugalware-release,with_distro="frugalware")
	AC_CHECK_FILE(/etc/mandrakelinux-release, with_distro="openmandriva")
	AC_CHECK_FILE(/etc/mandriva-release,with_distro="openmandriva")
	AC_CHECK_FILE(/etc/pardus-release,with_distro="pardus")
fi
with_distro=`echo ${with_distro} | tr '[[:upper:]]' '[[:lower:]]'`

if test "z$with_distro" = "z"; then
	with_distro="unknown"
fi
case $with_distro in
	ubuntu)
		distroconf=default.conf.ubuntu
		;;
	redhat|centos|fedora|oracle|oracleserver)
		distroconf=default.conf.libvirt
		;;
	*)
		distroconf=default.conf.unknown
		;;
esac
AC_MSG_RESULT([$with_distro])
AM_CONDITIONAL([HAVE_DEBIAN], [test x"$with_distro" = "xdebian" -o x"$with_distro" = "xubuntu"])
AM_CONDITIONAL([DISTRO_UBUNTU], [test "x$with_distro" = "xubuntu"])

# Check for init system type
AC_MSG_CHECKING([for init system type])
AC_ARG_WITH([init-script],
	    [AC_HELP_STRING([--with-init-script@<:@=TYPE@<:@,TYPE,...@:>@@:>@],
			    [Type(s) of init script to install: sysvinit, systemd, upstart,
			     distro @<:@default=distro@:>@])],[],[with_init_script=distro])
case "$with_init_script" in
	distro)
		case $with_distro in
			fedora)
				init_script=systemd
				;;
			redhat|centos|oracle|oracleserver)
				init_script=sysvinit
				;;
			debian)
				init_script=upstart,systemd
				;;
			ubuntu)
				init_script=upstart
				;;
			*)
				echo -n "Linux distribution init system unknown."
				init_script=
				;;
		esac
		;;
	*)
		init_script=$with_init_script
		;;
esac

# Check valid init systems were given, run in subshell so we don't mess up IFS
(IFS="," ; for init_sys in $init_script;
do
	case "$init_sys" in
		none|sysvinit|systemd|upstart)
			;;
		*)
			exit 1
			;;
	esac
done) || AC_MSG_ERROR([Unknown init system type in $init_script])

AM_CONDITIONAL([INIT_SCRIPT_SYSV], [echo "$init_script" |grep -q "sysvinit"])
AM_CONDITIONAL([INIT_SCRIPT_SYSTEMD], [echo "$init_script" |grep -q "systemd"])
AM_CONDITIONAL([INIT_SCRIPT_UPSTART], [echo "$init_script" |grep -q "upstart"])
AC_MSG_RESULT($init_script)

AC_PATH_PROG(HELP2MAN, help2man, false // No help2man //)
AM_CONDITIONAL([HAVE_HELP2MAN], [test "x$HELP2MAN" != "xfalse // No help2man //" ])

AS_AC_EXPAND(SBINDIR, "$sbindir")

AC_OUTPUT
