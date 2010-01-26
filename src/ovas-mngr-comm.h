/* OpenVAS Manager
 * $Id$
 * Description: See below.
 *
 * Authors:
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef OPENVAS_MANGER_OVAS_MNGR_COMM_H
#define OPENVAS_MANGER_OVAS_MNGR_COMM_H

#include <glib.h>
#include <gnutls/gnutls.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

/**
 * @file ovas-mngr-comm.h
 * @brief Protos for communication between openvas-manager and openvas-server.
 *
 * This file contains the protos for \ref ovas-mngr-comm.c
 */

int
send_to_server (const char *);

int
sendf_to_server (const char*, ...);

int
sendn_to_server (const void *, size_t);

int
connect_to_server (int, struct sockaddr_in*, gnutls_session_t*, gboolean);

int
write_string_to_server (gnutls_session_t*, char* const);

int
write_to_server_buffer (gnutls_session_t*);

unsigned int
to_server_buffer_space ();

#endif
