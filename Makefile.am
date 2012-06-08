SUBDIRS = po

bin_PROGRAMS = bin/wdm bin/wdmLogin
noinst_PROGRAMS = bin/TestLogin bin/wdmChooser bin/wdmPrefs

man1_MANS = doc/wdm.man doc/wdmLogin.man

noinst_LIBRARIES = bin/libwdm.a

dmdir = @DMDIR@
dm_DATA = configs/wdm-config \
	  configs/Xaccess \
	  configs/Xresources \
	  configs/Xservers

dm_SCRIPTS = configs/GiveConsole \
	     configs/TakeConsole \
	     configs/Xreset \
	     configs/Xsession \
	     configs/Xsetup_0 \
	     configs/Xstartup

EXTRA_DIST = ABOUT-NLS \
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
	     TODO

DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

bin_wdm_CFLAGS = $(XCFLAGS) $(WCFLAGS) $(SELINUX_CFLAGS)
bin_wdm_LDFLAGS = $(XLDFLAGS) $(WLDFLAGS)
bin_wdm_LDADD = bin/libwdm.a \
		$(XLIBS) $(WLIBS) $(PASSWDLIB) $(SELINUX_LIBS) \
		-lXmu -lXau -lXdmcp
bin_wdm_SOURCES = src/wdm/access.c \
		  src/wdm/auth.c \
		  src/wdm/choose.c \
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

bin_TestLogin_CFLAGS = $(XCFLAGS) $(WCFLAGS)
bin_TestLogin_LDFLAGS = $(XLDFLAGS) $(WLDFLAGS)
bin_TestLogin_LDADD = bin/libwdm.a \
		      $(XLIBS) $(WLIBS)
bin_TestLogin_SOURCES = src/TestLogin/TestLogin.c

bin_wdmChooser_CFLAGS = $(XCFLAGS) $(WCFLAGS)
bin_wdmChooser_LDFLAGS = $(XLDFLAGS) $(WLDFLAGS)
bin_wdmChooser_LDADD = bin/libwdm.a \
		       $(XLIBS) $(WLIBS)
bin_wdmChooser_SOURCES = src/wdmChooser/chooser.c

bin_wdmPrefs_CFLAGS = $(XCFLAGS) $(WCFLAGS)
bin_wdmPrefs_LDFLAGS = $(XLDFLAGS) $(WLDFLAGS)
bin_wdmPrefs_LDADD = bin/libwdm.a \
		     $(XLIBS) $(WLIBS)
bin_wdmPrefs_SOURCES = src/wdmPrefs/prefs.c \
		       src/wdmPrefs/testPanel2.c \
		       src/wdmPrefs/testPanel.c

bin_wdmLogin_CFLAGS = $(XCFLAGS) $(WCFLAGS)
bin_wdmLogin_LDFLAGS = $(XLDFLAGS) $(WLDFLAGS)
bin_wdmLogin_LDADD = bin/libwdm.a \
		     $(XLIBS) $(WLIBS)
bin_wdmLogin_SOURCES = src/wdmLogin/config.c \
		       src/wdmLogin/Login.c

bin_libwdm_a_CFLAGS = $(XCFLAGS) $(WCFLAGS)
bin_libwdm_a_SOURCES = src/libwdm/debug.c \
		       src/libwdm/environment.c \
		       src/libwdm/names.c \
		       src/libwdm/plcheckers.c

ACLOCAL_AMFLAGS = -I m4
