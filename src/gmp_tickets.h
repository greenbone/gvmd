/* Copyright (C) 2018-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
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
