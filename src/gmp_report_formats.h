/* Copyright (C) 2020-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_GMP_REPORT_FORMATS_H
#define _GVMD_GMP_REPORT_FORMATS_H

#include "gmp_base.h"

#include <gvm/base/array.h>
#include <gvm/util/xmlutils.h>

void
create_report_format_start (gmp_parser_t *, const gchar **, const gchar **);

void
create_report_format_element_start (gmp_parser_t *, const gchar *, const gchar **,
                                const gchar **);

int
create_report_format_element_end (gmp_parser_t *, GError **error, const gchar *);

void
create_report_format_element_text (const gchar *, gsize);

void
params_options_free (array_t *);

void
parse_report_format_entity (entity_t, const char **, char **, char **,
                            char **, char **, char **, char **,
                            array_t **, array_t **, array_t **, char **,
                            char **);

#endif /* not _GVMD_GMP_REPORT_FORMATS_H */
