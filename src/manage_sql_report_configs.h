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

#ifndef _GVMD_MANAGE_SQL_REPORT_CONFIGS_H
#define _GVMD_MANAGE_SQL_REPORT_CONFIGS_H

#include "manage.h"
#include "manage_sql.h"

#include <glib.h>


const char**
report_config_filter_columns ();

column_t*
report_config_select_columns ();

int
restore_report_config (const char *);

void
delete_report_configs_user (user_t);

gboolean
inherit_report_configs (user_t, user_t);



#endif /* not _GVMD_MANAGE_SQL_REPORT_CONFIGS_H */
