/*

Copyright 1988, 1998  The Open Group

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation.

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of The Open Group shall
not be used in advertising or otherwise to promote the sale, use or
other dealings in this Software without prior written authorization
from The Open Group.

*/
/*
 * wdm - WINGs Display Manager
 * Author:  Keith Packard, MIT X Consortium
 */

#include <X11/Xos.h>

#if defined(SVR4) || defined(USG)
#include <termios.h>
#else
#include <sys/ioctl.h>
#endif
#if defined(__osf__) || defined(linux) || defined(__GNU__) || defined(__CYGWIN__) \
	|| (defined(IRIX) && !defined(_IRIX4))
#define setpgrp setpgid
#endif
#include <errno.h>
#include <sys/types.h>
#define Pid_t pid_t

#include <stdlib.h>

#include <dm.h>
#include <wdmlib.h>

void BecomeOrphan(void)
{
	Pid_t child_id;

	/*
	 * fork so that the process goes into the background automatically. Also
	 * has a nice side effect of having the child process get inherited by
	 * init (pid 1).
	 * Separate the child into its own process group before the parent
	 * exits.  This eliminates the possibility that the child might get
	 * killed when the init script that's running wdm exits.
	 */

	child_id = fork();
	switch (child_id) {
	case 0:
		/* child */
		break;
	case -1:
		/* error */
		WDMError("daemon fork failed, errno = %d\n", errno);
		break;

	default:
		/* parent */

		exit(0);
	}
}

void BecomeDaemon(void)
{
	daemon(0, 0);
}
