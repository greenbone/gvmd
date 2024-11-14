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
 * @file manage_report_configs.c
 * @brief GVM management layer: Report configs.
 *
 * Non-SQL report config code for the GVM management layer.
 */

#include "manage_sql.h"
#include "manage_report_configs.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Find a report config for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of report config.
 * @param[out]  report_config  Report config return, 0 if successfully failed to
 *                             find report_config.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find report_config), TRUE
 *         on error.
 */
gboolean
find_report_config_with_permission (const char *uuid,
                                    report_config_t *report_config,
                                    const char *permission)
{
  return find_resource_with_permission ("report_config", uuid, report_config,
                                        permission, 0);
}

/**
 * @brief Free a report config parameter data struct.
 *
 * @param[in]  param  The parameter to free.
 */
void
report_config_param_data_free (report_config_param_data_t *param)
{
  if (param == NULL)
    return;

  g_free (param->name);
  g_free (param->value);
  g_free (param);
}

/**
 * @brief Return whether a report config is writable.
 *
 * @param[in]  report_config Report Config.
 *
 * @return 1 if writable, else 0.
 */
int
report_config_writable (report_config_t report_config)
{
  return report_config_in_use (report_config) == 0;
}

/**
 * @brief Return whether a trashcan report config is writable.
 *
 * @param[in]  report_config  Report Config.
 *
 * @return 1 if writable, else 0.
 */
int
trash_report_config_writable (report_config_t report_config)
{
  return trash_report_config_in_use (report_config) == 0;
}
