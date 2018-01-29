About Greenbone Vulnerability Manager
-------------------------------------

The Greenbone Vulnerability Manager is the central management service between
security scanners and the user clients.

It manages the storage of any vulnerability management configurations and of the
scan results. Access to data, control commands and workflows is offered via the
XML-based Greenbone Management Protocol (GMP). The primary scanner 'OpenVAS Scanner'
is controlled directly via protocol OTP while any other remote scanner is coupled
with the Open Scanner Protocol (OSP).

Greenbone Vulnerability Manager is licensed under GNU General Public License
Version 2 or any later version.  Please see file COPYING for details.

All parts of Greenbone Vulnerability Manager are Copyright (C) by Greenbone
Networks GmbH (see http://www.greenbone.net).


Howto use
---------

Starting Greenbone Vulnerability Manager:

In case everything was installed using the defaults, then starting the manager
can be done with this simple command:

    gvmd


A command like

    gvmd --update

or

    gvmd --rebuild

will update the Manager's NVT cache, and then exit.  The cache must be
updated every time the OpenVAS Scanner syncs with the NVT feed.  The --rebuild
option is faster as it locks the database the entire time, whereas --update
allows clients to access the Manager during the update.

An update within a running Manager can also be invoked by sending the main
Manager process the SIGHUP signal (signal number 1).


To see all available command line options of gvmd enter this command:

    gvmd --help
