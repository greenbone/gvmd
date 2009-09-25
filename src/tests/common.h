/* Common test utilities header.
 * $Id$
 * Description: Header for common test utilities.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
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

#ifndef COMMON_H
#define COMMON_H

#include <glib.h>
#include <gnutls/gnutls.h>
#include <stdio.h>

/* @todo Only include these in tests that use them. */
#include <openvas/base/openvas_string.h>
#include <openvas/omp.h>
#include <openvas/openvas_server.h>

/* Communication. */

int
connect_to_manager_host_port (gnutls_session_t *, const char*, int);

int
connect_to_manager (gnutls_session_t *);

int
close_manager_connection (int, gnutls_session_t);

/* Setup. */

void
setup_test ();

#endif /* not COMMON_H */
