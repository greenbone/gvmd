/* Copyright (C) 2009-2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file gmp.h
 * @brief Headers for the GMP library.
 */

#ifndef _GVMD_GMP_H
#define _GVMD_GMP_H

#include "manage.h"
#include "types.h"

#include <glib.h>
#include <gnutls/gnutls.h>
#include <gvm/util/serverutils.h>
#include <sys/types.h>

/**
 * @brief The size of the \ref to_client data buffer, in bytes.
 */
#define TO_CLIENT_BUFFER_SIZE 26214400

/**
 * @brief The maximum length in bytes for long result text like the description.
 */
#define TRUNCATE_TEXT_LENGTH 10000000

/**
 * @brief The text to append when text is truncated.
 */
#define TRUNCATE_TEXT_SUFFIX "[...]\n(text truncated)"

int
init_gmp (GSList *, const db_conn_info_t *, int, int, int, int,
          manage_connection_forker_t, int);

void
init_gmp_process (const db_conn_info_t *, int (*) (const char *, void *),
                  void *, gchar **);

int
process_gmp_client_input ();

/** @todo As described in gmp.c, probably should be replaced by gmp_parser_t. */
extern char to_client[];
extern buffer_size_t to_client_start;
extern buffer_size_t to_client_end;

#endif /* not _GVMD_MANAGE_H */
