/* Copyright (C) 2020-2022 Greenbone AG
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
 * @file manage_sql_alerts.c
 * @brief GVM management layer: Alert SQL
 *
 * Alert SQL for the GVM management layer.
 */

#include "manage_alerts.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Frees a alert_report_data_t struct, including contained data.
 *
 * @param[in]  data   The struct to free.
 */
void
alert_report_data_free (alert_report_data_t *data)
{
  if (data == NULL)
    return;

  alert_report_data_reset (data);
  g_free (data);
}

/**
 * @brief Frees content of an alert_report_data_t, but not the struct itself.
 *
 * @param[in]  data   The struct to free.
 */
void
alert_report_data_reset (alert_report_data_t *data)
{
  if (data == NULL)
    return;

  g_free (data->content_type);
  g_free (data->local_filename);
  g_free (data->remote_filename);
  g_free (data->report_format_name);

  memset (data, 0, sizeof (alert_report_data_t));
}
