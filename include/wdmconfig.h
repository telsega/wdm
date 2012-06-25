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

#endif							/* __WDMCONFIG_H */
