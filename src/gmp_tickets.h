/* Copyright (C) 2018 Greenbone Networks GmbH
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

#ifndef _GVMD_GMP_TICKETS_H
#define _GVMD_GMP_TICKETS_H

#include "gmp_base.h"
/* This is only needed for result_t, which ideally would come from a smaller
 * include file. */
#include "manage.h"

void
get_tickets_start (const gchar **, const gchar **);

void
get_tickets_run (gmp_parser_t *, GError **);

void
create_ticket_start (gmp_parser_t *, const gchar **, const gchar **);

void
create_ticket_element_start (gmp_parser_t *, const gchar *, const gchar **,
                             const gchar **);

int
create_ticket_element_end (gmp_parser_t *, GError **error, const gchar *);

void
create_ticket_element_text (const gchar *, gsize);

void
modify_ticket_start (gmp_parser_t *, const gchar **, const gchar **);

void
modify_ticket_element_start (gmp_parser_t *, const gchar *, const gchar **,
                             const gchar **);

int
modify_ticket_element_end (gmp_parser_t *, GError **error, const gchar *);

void
modify_ticket_element_text (const gchar *, gsize);

int
buffer_result_tickets_xml (GString *, result_t);

#endif /* not _GVMD_GMP_TICKETS_H */
