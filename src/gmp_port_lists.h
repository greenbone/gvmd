/* Copyright (C) 2020 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#ifndef _GVMD_GMP_PORT_LISTS_H
#define _GVMD_GMP_PORT_LISTS_H

#include "gmp_base.h"
#include "manage.h"

void
create_port_list_start (gmp_parser_t *, const gchar **, const gchar **);

void
create_port_list_element_start (gmp_parser_t *, const gchar *, const gchar **,
                                const gchar **);

int
create_port_list_element_end (gmp_parser_t *, GError **error, const gchar *);

void
create_port_list_element_text (const gchar *, gsize);

void
parse_port_list_entity (entity_t, const char **, char **, char **, array_t **);

#endif /* not _GVMD_GMP_PORT_LISTS_H */
