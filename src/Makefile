# OpenVAS
# $Id$
# Description: Makefile for the OpenVAS Manager
#
# Authors:
# Jan-Oliver Wagner <jan-oliver.wagner@intevation.de>
#
# Copyright:
# Copyright (C) 2008 Intevation GmbH
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

# run "make" this way (if necessary):
# OPENVAS_LIB_INSTALL_DIR=/your/path/to/lib/ OPENVAS_HEADER_INSTALL_DIR=/your/path/to/include make

LIBS = -L$(OPENVAS_LIB_INSTALL_DIR) -lgnutls -lopenvas
CFLAGS = -Wall -I$(OPENVAS_HEADER_INSTALL_DIR)

all: openvasmd

openvasmd.o: openvasmd.c
	$(CC) $(CFLAGS) `libopenvas-config --cflags` -c openvasmd.c

openvasmd: openvasmd.o
	$(CC) $(LIBS) openvasmd.o -o openvasmd

clean:
	rm -f *.o openvasmd
