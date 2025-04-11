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

/**
 * @brief Create an alert from an existing alert.
 *
 * @param[in]  name          Name of new alert. NULL to copy from existing.
 * @param[in]  comment       Comment on new alert. NULL to copy from
 *                           existing.
 * @param[in]  alert_id      UUID of existing alert.
 * @param[out] new_alert     New alert.
 *
 * @return 0 success, 1 alert exists already, 2 failed to find existing
 *         alert, 99 permission denied, -1 error.
 */
int
copy_alert (const char* name, const char* comment, const char* alert_id,
            alert_t* new_alert)
{
  int ret;
  alert_t new, old;

  assert (current_credentials.uuid);

  if (alert_id == NULL)
    return -1;

  sql_begin_immediate ();

  ret = copy_resource_lock ("alert", name, comment, alert_id,
                            "event, condition, method, filter, active",
                            1, &new, &old);
  if (ret)
    {
      sql_rollback ();
      return ret;
    }

  /* Copy the alert condition data */
  sql ("INSERT INTO alert_condition_data (alert, name, data)"
       " SELECT %llu, name, data FROM alert_condition_data"
       "  WHERE alert = %llu;",
       new,
       old);

  /* Copy the alert event data */
  sql ("INSERT INTO alert_event_data (alert, name, data)"
       " SELECT %llu, name, data FROM alert_event_data"
       "  WHERE alert = %llu;",
       new,
       old);

  /* Copy the alert method data */
  sql ("INSERT INTO alert_method_data (alert, name, data)"
       " SELECT %llu, name, data FROM alert_method_data"
       "  WHERE alert = %llu;",
       new,
       old);

  sql_commit ();
  if (new_alert) *new_alert = new;
  return 0;
}
