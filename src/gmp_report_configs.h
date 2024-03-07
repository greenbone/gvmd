/* Copyright (C) 2024 Greenbone AG
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
 * @file gmp_report_formats.h
 * @brief GVM GMP layer: Report Configs headers
 *
 * Headers for GMP report configurations.
 */

#ifndef _GVMD_GMP_REPORT_CONFIGS_H
#define _GVMD_GMP_REPORT_CONFIGS_H

#include "gmp_base.h"

#include <gvm/base/array.h>
#include <gvm/util/xmlutils.h>

void
create_report_config_start (gmp_parser_t *, const gchar **, const gchar **);

void
create_report_config_element_start (gmp_parser_t *, const gchar *, const gchar **,
                                    const gchar **);

int create_report_config_element_end (gmp_parser_t*, GError**, const gchar*);

void
create_report_config_element_text (const gchar *, gsize);

void
modify_report_config_start (gmp_parser_t *, const gchar **, const gchar **);

void
modify_report_config_element_start (gmp_parser_t *, const gchar *, const gchar **,
                                const gchar **);

int
modify_report_config_element_end (gmp_parser_t *, GError **error, const gchar *);

void
modify_report_config_element_text (const gchar *, gsize);

#endif /* not _GVMD_GMP_REPORT_CONFIGS_H */