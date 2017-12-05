/* OpenVAS Manager
 * $Id$
 * Description: Headers for OpenVAS Manager: the OMP library.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

#ifndef OPENVAS_MANAGER_OMP_H
#define OPENVAS_MANAGER_OMP_H

#include "types.h"
#include <openvas/misc/openvas_server.h>
#include <glib.h>
#include <gnutls/gnutls.h>
#include <sys/types.h>

/**
 * @brief The size of the \ref to_client data buffer, in bytes.
 */
#define TO_CLIENT_BUFFER_SIZE 26214400

int
init_omp (GSList*, int, const gchar*, int, int, int, int, void (*) (),
          int (*) (openvas_connection_t *, gchar*),
          int);

void
init_omp_process (int, const gchar*, int (*) (const char*, void*), void*,
                  gchar **);

int
process_omp_client_input ();

int
process_omp_change ();

/** @todo As described in omp.c, probably should be replaced by omp_parser_t. */
extern char to_client[];
extern buffer_size_t to_client_start;
extern buffer_size_t to_client_end;

#endif
