[![CircleCI](https://circleci.com/gh/greenbone/gvm/tree/master.svg?style=svg)](https://circleci.com/gh/greenbone/gvm/tree/master)

# About Greenbone Vulnerability Manager

The Greenbone Vulnerability Manager is the central management service between
security scanners and the user clients.

It manages the storage of any vulnerability management configurations and of the
scan results. Access to data, control commands and workflows is offered via the
XML-based Greenbone Management Protocol (GMP). The primary scanner
*[OpenVAS Scanner](https://github.com/greenbone/openvas-scanner)*
is controlled directly via protocol OTP while any other remote scanner is coupled
with the Open Scanner Protocol (OSP).

Greenbone Vulnerability Manager is licensed under GNU General Public License
Version 2 or any later version.  Please see file [COPYING](COPYING) for details.

All parts of Greenbone Vulnerability Manager are Copyright (C) by Greenbone
Networks GmbH (see http://www.greenbone.net).


# Howto use

Starting Greenbone Vulnerability Manager:

In case everything was installed using the defaults, then starting the manager
daemon can be done with this simple command:

```sh
    gvmd
```

To see all available command line options of gvmd enter this command:

```sh
    gvmd --help
```
