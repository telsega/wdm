ACLOCAL_AMFLAGS = -I m4

SUBDIRS = po

do_subst = $(SED) \
	   -e 's,[@]DEF_SERVER[@],$(DEF_SERVER),g' \
	   -e 's,[@]DMDIR[@],$(DMDIR),g' \
	   -e 's,[@]GFXDIR[@],$(GFXDIR),g' \
	   -e 's,[@]LOGDIR[@],$(LOGDIR),g' \
	   -e 's,[@]PIXMAPCOMMENT[@],$(PIXMAPCOMMENT),g' \
	   -e 's,[@]PIXMAPFILE[@],$(PIXMAPFILE),g' \
	   -e 's,[@]RUNDIR[@],$(RUNDIR),g' \
	   -e 's,[@]SHUTDOWN[@],$(SHUTDOWN),g' \
	   -e 's,[@]WMLIST[@],$(WMLIST),g' \
	   -e 's,[@]exec_prefix[@],$(exec_prefix),g'

SUFFIXES = .in

.in:
	$(AM_V_GEN)$(do_subst) > $@ < $<

bin_PROGRAMS = bin/wdm bin/wdmLogin
noinst_PROGRAMS = bin/TestLogin bin/wdmChooser bin/wdmPrefs

man1_MANS = doc/wdm.man doc/wdmLogin.man

dmdir = @DMDIR@
dm_DATA = configs/Xaccess \
	  configs/Xresources \
	  configs/Xservers \
	  configs/wdm-config \
	  configs/wdmLogin-config

dm_SCRIPTS = configs/GiveConsole \
	     configs/TakeConsole \
	     configs/Xreset \
	     configs/Xsession \
	     configs/Xsetup_0 \
	     configs/Xstartup

gfxdir = @GFXDIR@
dist_gfx_DATA = pixmaps/Eagle.xpm \
		pixmaps/Earth.jpg \
		pixmaps/Earth200x130.xpm \
		pixmaps/GnuLinux-logo.jpg \
		pixmaps/Stars.jpg \
		pixmaps/StarsLogo.jpg \
		pixmaps/gnuLogo.xpm

CLEANFILES = configs/GiveConsole \
	     configs/TakeConsole \
	     configs/Xreset \
	     configs/Xservers \
	     configs/Xstartup \
	     configs/wdm-config

if PAM
pamdir = @PAMDIR@
pam_DATA = configs/wdm
endif

configs = configs/GiveConsole.in \
	  configs/TakeConsole.in \
	  configs/Xaccess \
	  configs/Xreset.in \
	  configs/Xresources \
	  configs/Xservers.in \
	  configs/Xsession \
	  configs/Xsetup_0 \
	  configs/Xstartup.in \
	  configs/wdm \
	  configs/wdm-config.in \
	  configs/wdmLogin-config

EXTRA_DIST = $(configs) \
	     doc/wdm.man.in \
	     doc/wdmLogin.man \
	     ABOUT-NLS \
	     AUTHORS \
	     COPYING \
	     NASA_image_guideline.html \
	     NEWS \
	     README \
	     README.aa \
	     README.config \
	     README.newGnuLinuxlogo \
	     README.pam \
	     README.pixmaps \
	     README.voins \
	     TODO \
	     wdm.spec

AM_CFLAGS = -DLOCALEDIR=\"$(localedir)\"

noinst_HEADERS = include/consolekit.h \
		 include/dm_auth.h \
		 include/dm.h \
		 include/dm_socket.h \
		 include/gettext.h \
		 include/greet.h \
		 include/runtest.h \
		 include/wdmconfig.h \
		 include/wdm.h \
		 include/wdmlib.h \
		 include/wdmLogin.h \
		 include/wdmPrefs.h

noinst_LIBRARIES = bin/libwdm.a

bin_wdm_CPPFLAGS = $(XLIB_CFLAGS) $(WINGS_CFLAGS) $(SELINUX_CFLAGS) $(DBUS_CFLAGS)
bin_wdm_LDADD = bin/libwdm.a \
		$(XLIB_LIBS) $(WINGS_LIBS) $(PASSWDLIB) $(SELINUX_LIBS) $(DBUS_LIBS) $(AUDIT_LIBS) \
		-lXmu -lXau -lXdmcp
bin_wdm_SOURCES = src/wdm/access.c \
		  src/wdm/auth.c \
		  src/wdm/choose.c \
		  src/wdm/consolekit.c \
		  src/wdm/daemon.c \
		  src/wdm/dm.c \
		  src/wdm/dpylist.c \
		  src/wdm/file.c \
		  src/wdm/genauth.c \
		  src/wdm/Greet.c \
		  src/wdm/loghelpers.c \
		  src/wdm/mitauth.c \
		  src/wdm/netaddr.c \
		  src/wdm/policy.c \
		  src/wdm/protodpy.c \
		  src/wdm/reset.c \
		  src/wdm/resource.c \
		  src/wdm/server.c \
		  src/wdm/session.c \
		  src/wdm/socket.c \
		  src/wdm/util.c \
		  src/wdm/verify.c \
		  src/wdm/xdmcp.c

bin_TestLogin_CPPFLAGS = $(XLIB_CFLAGS) $(WINGS_CFLAGS)
bin_TestLogin_LDADD = bin/libwdm.a \
		      $(XLIB_LIBS) $(WINGS_LIBS)
bin_TestLogin_SOURCES = src/TestLogin/TestLogin.c

bin_wdmChooser_CPPFLAGS = $(XLIB_CFLAGS) $(WINGS_CFLAGS)
bin_wdmChooser_LDADD = bin/libwdm.a \
		       $(XLIB_LIBS) $(WINGS_LIBS)
bin_wdmChooser_SOURCES = src/wdmChooser/chooser.c

bin_wdmPrefs_CPPFLAGS = $(XLIB_CFLAGS) $(WINGS_CFLAGS)
bin_wdmPrefs_LDADD = bin/libwdm.a \
		     $(XLIB_LIBS) $(WINGS_LIBS)
bin_wdmPrefs_SOURCES = src/wdmPrefs/prefs.c \
		       src/wdmPrefs/testPanel2.c \
		       src/wdmPrefs/testPanel.c

bin_wdmLogin_CPPFLAGS = $(XLIB_CFLAGS) $(XINERAMA_CFLAGS) $(WINGS_CFLAGS) $(WRLIB_CFLAGS)
bin_wdmLogin_LDADD = bin/libwdm.a \
		     $(XLIB_LIBS) $(XINERAMA_LIBS) $(WINGS_LIBS) $(WRLIB_LIBS) $(LIBINTL)
bin_wdmLogin_SOURCES = src/wdmLogin/config.c \
		       src/wdmLogin/Login.c

bin_libwdm_a_CPPFLAGS = $(XLIB_CFLAGS) $(WINGS_CFLAGS)
bin_libwdm_a_SOURCES = src/libwdm/debug.c \
		       src/libwdm/environment.c \
		       src/libwdm/names.c \
		       src/libwdm/plcheckers.c
