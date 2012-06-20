/*
Copyright 1989, 1998  The Open Group

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation.

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of The Open Group shall not be
used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization from The Open Group.
 *
 * Author:  Keith Packard, MIT X Consortium
 */
/*
 * protodpy.c
 *
 * manage a collection of proto-displays.  These are displays for
 * which sessionID's have been generated, but no session has been
 * started.
 */

#include <dm.h>

#ifdef XDMCP

#include <sys/types.h>
#include <time.h>
#define Time_t time_t

#include <wdmlib.h>

#include <WINGs/WUtil.h>

static WMArray *protoDisplays = NULL;

struct _matchAddress {
	XdmcpNetaddr address;
	int addrlen;
	CARD16 displayNumber;
};

static int matchAddress(const struct protoDisplay *pdpy, struct _matchAddress *a)
{
	if (pdpy->displayNumber == a->displayNumber && addressEqual(a->address, a->addrlen, pdpy->address, pdpy->addrlen))
		return 1;
	return 0;
}

struct protoDisplay *FindProtoDisplay(XdmcpNetaddr address, int addrlen, CARD16 displayNumber)
{
	WDMDebug("FindProtoDisplay\n");
	if (protoDisplays != NULL) {
		int i;
		struct _matchAddress a;

		a.address = address;
		a.addrlen = addrlen;
		a.displayNumber = displayNumber;

		if ((i = WMFindInArray(protoDisplays, (WMMatchDataProc *) matchAddress, &a)) != WANotFound)
			return WMGetFromArray(protoDisplays, i);
	}
	return NULL;
}

static int matchTimeout(const struct protoDisplay *pdpy, Time_t *now)
{
	return pdpy->date < *now - PROTO_TIMEOUT;
}

static void TimeoutProtoDisplays(Time_t now)
{
	if (protoDisplays != NULL)
		WMRemoveFromArrayMatching(protoDisplays, (WMMatchDataProc *) matchTimeout, &now);
}

struct protoDisplay *NewProtoDisplay(XdmcpNetaddr address,
									 int addrlen,
									 CARD16 displayNumber, CARD16 connectionType, ARRAY8Ptr connectionAddress, CARD32 sessionID)
{
	struct protoDisplay *pdpy;
	Time_t date;

	WDMDebug("NewProtoDisplay\n");
	if (protoDisplays == NULL)
		protoDisplays = WMCreateArrayWithDestructor(0, (void (*) (void*)) DisposeProtoDisplay);

	time(&date);
	TimeoutProtoDisplays(date);
	pdpy = (struct protoDisplay *)malloc(sizeof *pdpy);
	if (!pdpy)
		return NULL;
	pdpy->address = (XdmcpNetaddr) malloc(addrlen);
	if (!pdpy->address) {
		free((char *)pdpy);
		return NULL;
	}
	pdpy->addrlen = addrlen;
	memmove(pdpy->address, address, addrlen);
	pdpy->displayNumber = displayNumber;
	pdpy->connectionType = connectionType;
	pdpy->date = date;
	if (!XdmcpCopyARRAY8(connectionAddress, &pdpy->connectionAddress)) {
		free((char *)pdpy->address);
		free((char *)pdpy);
		return NULL;
	}
	pdpy->sessionID = sessionID;
	pdpy->fileAuthorization = (Xauth *) NULL;
	pdpy->xdmcpAuthorization = (Xauth *) NULL;
	WMAddToArray(protoDisplays, pdpy);
	return pdpy;
}

void DisposeProtoDisplay(struct protoDisplay *pdpy)
{
	bzero(&pdpy->key, sizeof(pdpy->key));
	if (pdpy->fileAuthorization)
		XauDisposeAuth(pdpy->fileAuthorization);
	if (pdpy->xdmcpAuthorization)
		XauDisposeAuth(pdpy->xdmcpAuthorization);
	XdmcpDisposeARRAY8(&pdpy->connectionAddress);
	free((char *)pdpy->address);
	free((char *)pdpy);
}

#endif							/* XDMCP */
