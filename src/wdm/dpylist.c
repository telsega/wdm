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
 *
 * a simple linked list of known displays
 */

#include <dm.h>
#include <wdmlib.h>

#include <WINGs/WUtil.h>

static WMArray *displays = NULL;
static int no_xserver_started = 1;

int AnyDisplaysLeft(void)
{
	return no_xserver_started || (displays != NULL && WMGetArrayItemCount(displays) > 0);
}

void ForEachDisplay(void (*f) (struct display *))
{
	if (displays != NULL) {
		WMMapArray(displays, (void (*) (void *, void *)) f, NULL);
	}
}

#define matchEq(a, b) ((a) == (b))
#define defineFindDisplayBy(What, Type, Arg, Match) \
static int match##What(const struct display *d, Type *Arg) \
{ \
	return Match(*Arg, d->Arg); \
} \
\
struct display *FindDisplayBy##What(Type Arg) \
{ \
	if (displays != NULL) { \
		int i; \
\
		if ((i = WMFindInArray(displays, (WMMatchDataProc *) match##What, &Arg)) != WANotFound) \
			return WMGetFromArray(displays, i); \
	} \
\
	return NULL; \
}

defineFindDisplayBy(Name, char *, name, !strcmp);
defineFindDisplayBy(Pid, int, pid, matchEq);
defineFindDisplayBy(ServerPid, int, serverPid, matchEq);
#ifdef XDMCP
defineFindDisplayBy(SessionID, CARD32, sessionID, matchEq);

struct _matchAddress {
	XdmcpNetaddr addr;
	int addrlen;
	CARD16 displayNumber;
};

static int matchAddress(const struct display *d, struct _matchAddress *a)
{
	if (d->displayType.origin == FromXDMCP &&
		d->displayNumber == a->displayNumber && addressEqual(d->from, d->fromlen, a->addr, a->addrlen))
		return 1;
	return 0;
}

struct display *FindDisplayByAddress(XdmcpNetaddr addr, int addrlen, CARD16 displayNumber)
{
	if (displays != NULL) {
		int i;
		struct _matchAddress a;

		a.addr = addr;
		a.addrlen = addrlen;
		a.displayNumber = displayNumber;

		if ((i = WMFindInArray(displays, (WMMatchDataProc *) matchAddress, &a)) != WANotFound)
			return WMGetFromArray(displays, i);
	}

	return NULL;
}

#endif							/* XDMCP */

#undef defineFindDisplayBy
#undef matchEq

#define IfFree(x)  if (x) free ((char *) x)

void RemoveDisplay(struct display *old)
{
	if (displays != NULL)
		WMRemoveFromArrayMatching(displays, NULL, old);
}

static void freeDisplay(struct display *d)
{
	char **x;
	int i;

	IfFree(d->name);
	IfFree(d->class);
	for (x = d->argv; x && *x; x++)
		IfFree(*x);
	IfFree(d->argv);
	IfFree(d->resources);
	IfFree(d->xrdb);
	IfFree(d->setup);
	IfFree(d->startup);
	IfFree(d->reset);
	IfFree(d->session);
	IfFree(d->userPath);
	IfFree(d->systemPath);
	IfFree(d->systemShell);
	IfFree(d->failsafeClient);
	IfFree(d->chooser);
	if (d->authorizations) {
		for (i = 0; i < d->authNum; i++)
			XauDisposeAuth(d->authorizations[i]);
		free((char *)d->authorizations);
	}
	IfFree(d->clientAuthFile);
	if (d->authFile)
		(void)unlink(d->authFile);
	IfFree(d->authFile);
	IfFree(d->userAuthDir);
	for (x = d->authNames; x && *x; x++)
		IfFree(*x);
	IfFree(d->authNames);
	IfFree(d->authNameLens);
#ifdef XDMCP
	IfFree(d->peer);
	IfFree(d->from);
	XdmcpDisposeARRAY8(&d->clientAddr);
#endif
	free((char *)d);
}

struct display *NewDisplay(char *name, char *class)
{
	struct display *d;

	if (displays == NULL)
		displays = WMCreateArrayWithDestructor(0, (void (*) (void*)) freeDisplay);

	d = (struct display *)malloc(sizeof(struct display));
	if (!d) {
		WDMError("NewDisplay: out of memory");
		return 0;
	}
	d->name = malloc((unsigned)(strlen(name) + 1));
	if (!d->name) {
		WDMError("NewDisplay: out of memory");
		free((char *)d);
		return 0;
	}
	strcpy(d->name, name);
	if (class) {
		d->class = malloc((unsigned)(strlen(class) + 1));
		if (!d->class) {
			WDMError("NewDisplay: out of memory");
			free(d->name);
			free((char *)d);
			return 0;
		}
		strcpy(d->class, class);
	} else {
		d->class = (char *)0;
	}
	/* initialize every field to avoid possible problems */
	d->argv = 0;
	d->status = notRunning;
	d->pid = -1;
	d->serverPid = -1;
	d->state = NewEntry;
	d->resources = NULL;
	d->xrdb = NULL;
	d->setup = NULL;
	d->startup = NULL;
	d->reset = NULL;
	d->session = NULL;
	d->userPath = NULL;
	d->systemPath = NULL;
	d->systemShell = NULL;
	d->failsafeClient = NULL;
	d->chooser = NULL;
	d->authorize = FALSE;
	d->authorizations = NULL;
	d->authNum = 0;
	d->authNameNum = 0;
	d->clientAuthFile = NULL;
	d->authFile = NULL;
	d->userAuthDir = NULL;
	d->authNames = NULL;
	d->authNameLens = NULL;
	d->authComplain = 1;
	d->openDelay = 0;
	d->openRepeat = 0;
	d->openTimeout = 0;
	d->startAttempts = 0;
	d->startTries = 0;
	d->lastCrash = 0;
	d->terminateServer = 0;
	d->grabTimeout = 0;
#ifdef XDMCP
	d->sessionID = 0;
	d->peer = 0;
	d->peerlen = 0;
	d->from = 0;
	d->fromlen = 0;
	d->displayNumber = 0;
	d->useChooser = 0;
	d->clientAddr.data = NULL;
	d->clientAddr.length = 0;
	d->connectionType = 0;
#endif
	d->version = 1;				/* registered with The Open Group */

	WMAddToArray(displays, d);

	no_xserver_started = 0;

	return d;
}
