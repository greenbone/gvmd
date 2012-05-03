/* OpenVAS Manager
 * $Id$
 * Description: Headers for OpenVAS Manager: the OMP daemon.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
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

#ifndef OPENVAS_MANAGER_OMPD_H
#define OPENVAS_MANAGER_OMPD_H

#include "types.h"
#include <glib.h>
#include <gnutls/gnutls.h>

int
init_ompd (GSList*, int, const gchar*);

void
init_ompd_process (const gchar *, gchar **);

int
serve_omp (gnutls_session_t*, gnutls_session_t*,
           gnutls_certificate_credentials_t*,
           gnutls_certificate_credentials_t*,
           int, int*, const gchar*, gchar**);

/** @todo Temporarily declared here, for omp.c SEND_TO_CLIENT. */
extern char to_client[];
extern buffer_size_t to_client_start;
extern buffer_size_t to_client_end;

#endif
