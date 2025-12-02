/* Copyright (C) 2019-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_GMP_CONFIGS_H
#define _GVMD_GMP_CONFIGS_H

#include "gmp_base.h"

#include <gvm/base/array.h>
#include <gvm/util/xmlutils.h>

/* create_config */

void
create_config_start (gmp_parser_t *, const gchar **, const gchar **);

void
create_config_element_start (gmp_parser_t *, const gchar *, const gchar **,
                             const gchar **);

int
create_config_element_end (gmp_parser_t *, GError **error, const gchar *);

void
create_config_element_text (const gchar *, gsize);

int
parse_config_entity (entity_t, const char **, char **, char **,
                     char **, int *, array_t **, array_t **, char **);

/* modify_config */

void
modify_config_start (gmp_parser_t *, const gchar **, const gchar **);

void
modify_config_element_start (gmp_parser_t *, const gchar *, const gchar **,
                             const gchar **);

int
modify_config_element_end (gmp_parser_t *, GError **error, const gchar *);

void
modify_config_element_text (const gchar *, gsize);

#endif /* not _GVMD_GMP_CONFIGS_H */
