#ifndef __WDMCONFIG_H
#define __WDMCONFIG_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* wdm stuff which should always be defined */

#ifdef HAVE_PAM
#define USE_PAM
#else
#ifdef HAVE_SHADOW
#define USESHADOW
#endif
#endif

/* per kde/kdm, too many systems have trouble with secure rpc */
/* disable secure rpc 'for now' */
#undef SECURE_RPC

#endif							/* __WDMCONFIG_H */
