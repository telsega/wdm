/*
 * wdm - WINGs display manager
 * Copyright (C) 2003 Alexey Voinov <voins@voins.program.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * chooser.c: wdmChooser program. replacement for chooser from xdm
 */
#include <wdmlib.h>
#include <stdlib.h>

void
closeAction(WMWidget *self, void *data)
{
	WMDestroyWidget(self);
	exit(0);
}

int main(int argc, char *argv[])
{
	WMScreen *scr;
	WMWindow *win;

	WMInitializeApplication("wdmChooser", &argc, argv);
	scr = WMOpenScreen(NULL);
	if(scr == NULL)
		WDMPanic("could not initialize Screen");


	win = WMCreateWindow(scr, "wdmChooser");
	WMResizeWidget(win, 600, 300);
	WMMoveWidget(win, 100, 100);
	WMRealizeWidget(win);
	WMMapWidget(win);
	WMSetWindowCloseAction(win, closeAction, NULL);
	WMSetWindowTitle(win, "wdmChooser");
	WMScreenMainLoop(scr);

	return 0;
}
