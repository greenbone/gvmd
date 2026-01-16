/* Copyright (C) 2024 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report configs SQL.
 *
 * SQL report config code for the GVM management layer.
 */

#ifndef _GVMD_MANAGE_SQL_REPORT_CONFIGS_H
#define _GVMD_MANAGE_SQL_REPORT_CONFIGS_H

#include "manage_report_configs.h"
#include "manage_resources.h"

#include <glib.h>

const char**
report_config_filter_columns ();

column_t*
report_config_select_columns ();

int
restore_report_config (const char *);

void
delete_report_configs_user (user_t);

#endif /* not _GVMD_MANAGE_SQL_REPORT_CONFIGS_H */
