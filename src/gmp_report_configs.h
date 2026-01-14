/* Copyright (C) 2024 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
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