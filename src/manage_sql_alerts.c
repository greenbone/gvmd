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
#include "manage_acl.h"
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

/**
 * @brief Delete an alert.
 *
 * @param[in]  alert_id  UUID of alert.
 * @param[in]  ultimate      Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 fail because a task refers to the alert, 2 failed
 *         to find target, 99 permission denied, -1 error.
 */
int
delete_alert (const char *alert_id, int ultimate)
{
  alert_t alert = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_alert") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_alert_with_permission (alert_id, &alert, "delete_alert"))
    {
      sql_rollback ();
      return -1;
    }

  if (alert == 0)
    {
      if (find_trash ("alert", alert_id, &alert))
        {
          sql_rollback ();
          return -1;
        }
      if (alert == 0)
        {
          sql_rollback ();
          return 2;
        }
      if (ultimate == 0)
        {
          /* It's already in the trashcan. */
          sql_commit ();
          return 0;
        }

      /* Check if it's in use by a task in the trashcan. */
      if (sql_int ("SELECT count(*) FROM task_alerts"
                   " WHERE alert = %llu"
                   " AND alert_location = " G_STRINGIFY (LOCATION_TRASH) ";",
                   alert))
        {
          sql_rollback ();
          return 1;
        }

      permissions_set_orphans ("alert", alert, LOCATION_TRASH);
      tags_remove_resource ("alert", alert, LOCATION_TRASH);

      sql ("DELETE FROM alert_condition_data_trash WHERE alert = %llu;",
           alert);
      sql ("DELETE FROM alert_event_data_trash WHERE alert = %llu;",
           alert);
      sql ("DELETE FROM alert_method_data_trash WHERE alert = %llu;",
           alert);
      sql ("DELETE FROM alerts_trash WHERE id = %llu;", alert);
      sql_commit ();
      return 0;
    }

  if (ultimate == 0)
    {
      alert_t trash_alert;

      if (sql_int ("SELECT count(*) FROM task_alerts"
                   " WHERE alert = %llu"
                   " AND alert_location = " G_STRINGIFY (LOCATION_TABLE)
                   " AND (SELECT hidden < 2 FROM tasks"
                   "      WHERE id = task_alerts.task);",
                   alert))
        {
          sql_rollback ();
          return 1;
        }

      sql ("INSERT INTO alerts_trash"
           " (uuid, owner, name, comment, event, condition, method, filter,"
           "  filter_location, active, creation_time, modification_time)"
           " SELECT uuid, owner, name, comment, event, condition, method,"
           "        filter, " G_STRINGIFY (LOCATION_TABLE) ", active,"
           "        creation_time, m_now ()"
           " FROM alerts WHERE id = %llu;",
           alert);

      trash_alert = sql_last_insert_id ();

      sql ("INSERT INTO alert_condition_data_trash"
           " (alert, name, data)"
           " SELECT %llu, name, data"
           " FROM alert_condition_data WHERE alert = %llu;",
           trash_alert,
           alert);

      sql ("INSERT INTO alert_event_data_trash"
           " (alert, name, data)"
           " SELECT %llu, name, data"
           " FROM alert_event_data WHERE alert = %llu;",
           trash_alert,
           alert);

      sql ("INSERT INTO alert_method_data_trash"
           " (alert, name, data)"
           " SELECT %llu, name, data"
           " FROM alert_method_data WHERE alert = %llu;",
           trash_alert,
           alert);

      /* Update the location of the alert in any trashcan tasks. */
      sql ("UPDATE task_alerts"
           " SET alert = %llu,"
           "     alert_location = " G_STRINGIFY (LOCATION_TRASH)
           " WHERE alert = %llu"
           " AND alert_location = " G_STRINGIFY (LOCATION_TABLE) ";",
           trash_alert,
           alert);

      permissions_set_locations ("alert", alert, trash_alert,
                                 LOCATION_TRASH);
      tags_set_locations ("alert", alert, trash_alert,
                          LOCATION_TRASH);
    }
  else if (sql_int ("SELECT count(*) FROM task_alerts"
                    " WHERE alert = %llu"
                    " AND alert_location = " G_STRINGIFY (LOCATION_TABLE) ";",
                    alert))
    {
      sql_rollback ();
      return 1;
    }
  else
    {
      permissions_set_orphans ("alert", alert, LOCATION_TABLE);
      tags_remove_resource ("alert", alert, LOCATION_TABLE);
    }

  sql ("DELETE FROM alert_condition_data WHERE alert = %llu;",
       alert);
  sql ("DELETE FROM alert_event_data WHERE alert = %llu;", alert);
  sql ("DELETE FROM alert_method_data WHERE alert = %llu;", alert);
  sql ("DELETE FROM alerts WHERE id = %llu;", alert);
  sql_commit ();
  return 0;
}

/**
 * @brief Return the UUID of an alert.
 *
 * @param[in]  alert  Alert.
 *
 * @return UUID of alert.
 */
char *
alert_uuid (alert_t alert)
{
  return sql_string ("SELECT uuid FROM alerts WHERE id = %llu;",
                     alert);
}

/**
 * @brief Return the owner of an alert.
 *
 * @param[in]  alert  Alert.
 *
 * @return Owner.
 */
user_t
alert_owner (alert_t alert)
{
  return sql_int64_0 ("SELECT owner FROM alerts WHERE id = %llu;",
                      alert);
}

/**
 * @brief Return the condition associated with an alert.
 *
 * @param[in]  alert  Alert.
 *
 * @return Condition.
 */
alert_condition_t
alert_condition (alert_t alert)
{
  return sql_int ("SELECT condition FROM alerts WHERE id = %llu;",
                  alert);
}

/**
 * @brief Return the method associated with an alert.
 *
 * @param[in]  alert  Alert.
 *
 * @return Method.
 */
alert_method_t
alert_method (alert_t alert)
{
  return sql_int ("SELECT method FROM alerts WHERE id = %llu;",
                  alert);
}
