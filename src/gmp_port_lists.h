/* Copyright (C) 2020-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_GMP_PORT_LISTS_H
#define _GVMD_GMP_PORT_LISTS_H

#include "gmp_base.h"

#include <gvm/base/array.h>
#include <gvm/util/xmlutils.h>

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
parse_port_list_entity (entity_t, const char **, char **, char **, array_t **,
                        char **);

#endif /* not _GVMD_GMP_PORT_LISTS_H */
