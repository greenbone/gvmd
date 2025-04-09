/* Copyright (C) 2019-2025 Greenbone AG
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

#include "manage_alerts.h"
#include "manage_sql.h"

/**
 * @file manage_sql_alerts.c
 * @brief GVM management layer: Alert SQL
 *
 * The Alert SQL for the GVM management layer.
 */

/**
 * @brief Find a alert for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of alert.
 * @param[out]  alert       Alert return, 0 if successfully failed to find alert.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find alert), TRUE on error.
 */
gboolean
find_alert_with_permission (const char* uuid, alert_t* alert,
                            const char *permission)
{
  return find_resource_with_permission ("alert", uuid, alert, permission, 0);
}
