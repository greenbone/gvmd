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
#include "manage_sql_alerts.h"

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
 * @brief Return the UUID of the owner of an alert.
 *
 * @param[in]  alert  Alert.
 *
 * @return UUID of owner.
 */
char *
alert_owner_uuid (alert_t alert)
{
  return sql_string ("SELECT uuid FROM users"
                     " WHERE id = (SELECT owner FROM alerts WHERE id = %llu);",
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

/**
 * @brief Count the number of alerts.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of alerts filtered set.
 */
int
alert_count (const get_data_t *get)
{
  static const char *filter_columns[] = ALERT_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = ALERT_ITERATOR_COLUMNS;
  static column_t trash_columns[] = ALERT_ITERATOR_TRASH_COLUMNS;
  return count ("alert", get, columns, trash_columns, filter_columns, 0, 0, 0,
                  TRUE);
}

/**
 * @brief Initialise an alert iterator, including observed alerts.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find alert, 2 failed to find filter (filt_id),
 *         -1 error.
 */
int
init_alert_iterator (iterator_t* iterator, get_data_t *get)
{
  static const char *filter_columns[] = ALERT_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = ALERT_ITERATOR_COLUMNS;
  static column_t trash_columns[] = ALERT_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "alert",
                            get,
                            columns,
                            trash_columns,
                            filter_columns,
                            0,
                            NULL,
                            NULL,
                            TRUE);
}

/**
 * @brief Return the event from an alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Event of the alert or NULL if iteration is complete.
 */
int
alert_iterator_event (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT);
  return ret;
}

/**
 * @brief Return the condition from an alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Condition of the alert or NULL if iteration is complete.
 */
int
alert_iterator_condition (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 1);
  return ret;
}

/**
 * @brief Return the method from an alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Method of the alert or NULL if iteration is complete.
 */
int
alert_iterator_method (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 2);
  return ret;
}

/**
 * @brief Return the filter from an alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Filter of the alert or NULL if iteration is complete.
 */
static filter_t
alert_iterator_filter (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return (filter_t) iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 3);
}

/**
 * @brief Return the filter UUID from an alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID of filter of the alert or NULL if iteration is complete.
 */
char *
alert_iterator_filter_uuid (iterator_t* iterator)
{
  filter_t filter;

  if (iterator->done) return NULL;

  filter = alert_iterator_filter (iterator);
  if (filter)
    {
      if (iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 4)
          == LOCATION_TABLE)
        return filter_uuid (filter);
      return trash_filter_uuid (filter);
    }
  return NULL;
}

/**
 * @brief Return the filter name from an alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name of filter of the alert or NULL if iteration is complete.
 */
char *
alert_iterator_filter_name (iterator_t* iterator)
{
  filter_t filter;

  if (iterator->done) return NULL;

  filter = alert_iterator_filter (iterator);
  if (filter)
    {
      if (iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 4)
          == LOCATION_TABLE)
        return filter_name (filter);
      return trash_filter_name (filter);
    }
  return NULL;
}

/**
 * @brief Return the location of an alert iterator filter.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 0 in table, 1 in trash.
 */
int
alert_iterator_filter_trash (iterator_t* iterator)
{
  if (iterator->done) return 0;
  if (alert_iterator_filter (iterator)
      && (iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 4)
          == LOCATION_TRASH))
    return 1;
  return 0;
}

/**
 * @brief Return the filter readable state from an alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Whether filter is readable.
 */
int
alert_iterator_filter_readable (iterator_t* iterator)
{
  filter_t filter;

  if (iterator->done) return 0;

  filter = alert_iterator_filter (iterator);
  if (filter)
    {
      char *uuid;
      uuid = alert_iterator_filter_uuid (iterator);
      if (uuid)
        {
          int readable;
          readable = acl_user_has_access_uuid
                      ("filter", uuid, "get_filters",
                       iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 4)
                       == LOCATION_TRASH);
          free (uuid);
          return readable;
        }
    }
  return 0;
}

/**
 * @brief Return the active state from an alert.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Method of the alert or NULL if iteration is complete.
 */
int
alert_iterator_active (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 5);
  return ret;
}

/**
 * @brief Initialise an alert data iterator.
 *
 * @param[in]  iterator   Iterator.
 * @param[in]  alert  Alert.
 * @param[in]  trash      Whether to iterate over trashcan alert data.
 * @param[in]  table      Type of data: "condition", "event" or "method",
 *                        corresponds to substring of the table to select
 *                        from.
 */
void
init_alert_data_iterator (iterator_t *iterator, alert_t alert,
                          int trash, const char *table)
{
  init_iterator (iterator,
                 "SELECT name, data FROM alert_%s_data%s"
                 " WHERE alert = %llu;",
                 table,
                 trash ? "_trash" : "",
                 alert);
}

/**
 * @brief Return the name from an alert data iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name of the alert data or NULL if iteration is complete.
 */
const char*
alert_data_iterator_name (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = iterator_string (iterator, 0);
  return ret;
}

/**
 * @brief Return the data from an alert data iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 *
 * @return Data of the alert data or NULL if iteration is complete.
 */
const char*
alert_data_iterator_data (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = iterator_string (iterator, 1);
  return ret;
}

/**
 * @brief Initialise a task alert iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  task      Task.
 */
void
init_task_alert_iterator (iterator_t* iterator, task_t task)
{
  gchar *owned_clause, *with_clause;
  get_data_t get;
  array_t *permissions;

  assert (task);

  get.trash = 0;
  permissions = make_array ();
  array_add (permissions, g_strdup ("get_alerts"));
  owned_clause = acl_where_owned ("alert", &get, 0, "any", 0, permissions, 0,
                                  &with_clause);
  array_free (permissions);

  init_iterator (iterator,
                 "%s"
                 " SELECT alerts.id, alerts.uuid, alerts.name"
                 " FROM alerts, task_alerts"
                 " WHERE task_alerts.task = %llu"
                 " AND task_alerts.alert = alerts.id"
                 " AND %s;",
                 with_clause ? with_clause : "",
                 task,
                 owned_clause);

  g_free (with_clause);
  g_free (owned_clause);
}

/**
 * @brief Get the UUID from a task alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (task_alert_iterator_uuid, 1);

/**
 * @brief Get the name from a task alert iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (task_alert_iterator_name, 2);

/**
 * @brief Initialise an alert task iterator.
 *
 * Iterate over all tasks that use the alert.
 *
 * @param[in]  iterator   Iterator.
 * @param[in]  alert  Alert.
 * @param[in]  ascending  Whether to sort ascending or descending.
 */
void
init_alert_task_iterator (iterator_t* iterator, alert_t alert,
                              int ascending)
{
  gchar *available, *with_clause;
  get_data_t get;
  array_t *permissions;

  assert (alert);

  get.trash = 0;
  permissions = make_array ();
  array_add (permissions, g_strdup ("get_tasks"));
  available = acl_where_owned ("task", &get, 1, "any", 0, permissions, 0,
                               &with_clause);
  array_free (permissions);

  init_iterator (iterator,
                 "%s"
                 " SELECT tasks.name, tasks.uuid, %s FROM tasks, task_alerts"
                 " WHERE tasks.id = task_alerts.task"
                 " AND task_alerts.alert = %llu"
                 " AND hidden = 0"
                 " ORDER BY tasks.name %s;",
                 with_clause ? with_clause : "",
                 available,
                 alert,
                 ascending ? "ASC" : "DESC");

  g_free (with_clause);
  g_free (available);
}

/**
 * @brief Return the name from an alert task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name of the task or NULL if iteration is complete.
 */
const char*
alert_task_iterator_name (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = iterator_string (iterator, 0);
  return ret;
}

/**
 * @brief Return the uuid from an alert task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID of the task or NULL if iteration is complete.
 */
const char*
alert_task_iterator_uuid (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = iterator_string (iterator, 1);
  return ret;
}

/**
 * @brief Get the read permission status from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if may read, else 0.
 */
int
alert_task_iterator_readable (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, 2);
}

/**
 * @brief Check for new SCAP SecInfo after an update.
 */
static void
check_for_new_scap ()
{
  if (manage_scap_loaded ())
    {
      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM scap.cves"
                   "  WHERE creation_time"
                   "        > coalesce (CAST ((SELECT value FROM meta"
                   "                           WHERE name"
                   "                                 = 'scap_check_time')"
                   "                          AS INTEGER),"
                   "                    0));"))
        event (EVENT_NEW_SECINFO, "cve", 0, 0);

      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM scap.cpes"
                   "  WHERE creation_time"
                   "        > coalesce (CAST ((SELECT value FROM meta"
                   "                           WHERE name"
                   "                                 = 'scap_check_time')"
                   "                          AS INTEGER),"
                   "                    0));"))
        event (EVENT_NEW_SECINFO, "cpe", 0, 0);
    }
}

/**
 * @brief Check for new CERT SecInfo after an update.
 */
static void
check_for_new_cert ()
{
  if (manage_cert_loaded ())
    {
      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM cert.cert_bund_advs"
                   "  WHERE creation_time"
                   "        > coalesce (CAST ((SELECT value FROM meta"
                   "                           WHERE name"
                   "                                 = 'cert_check_time')"
                   "                          AS INTEGER),"
                   "                    0));"))
        event (EVENT_NEW_SECINFO, "cert_bund_adv", 0, 0);

      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM cert.dfn_cert_advs"
                   "  WHERE creation_time"
                   "        > coalesce (CAST ((SELECT value FROM meta"
                   "                           WHERE name"
                   "                                 = 'cert_check_time')"
                   "                          AS INTEGER),"
                   "                    0));"))
        event (EVENT_NEW_SECINFO, "dfn_cert_adv", 0, 0);
    }
}

/**
 * @brief Check for updated SCAP SecInfo after an update.
 */
static void
check_for_updated_scap ()
{
  if (manage_scap_loaded ())
    {
      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM scap.cves"
                   "  WHERE modification_time"
                   "        > coalesce (CAST ((SELECT value FROM meta"
                   "                           WHERE name"
                   "                                 = 'scap_check_time')"
                   "                          AS INTEGER),"
                   "                    0)"
                   "  AND creation_time"
                   "      <= coalesce (CAST ((SELECT value FROM meta"
                   "                          WHERE name"
                   "                                = 'scap_check_time')"
                   "                         AS INTEGER),"
                   "                   0));"))
        event (EVENT_UPDATED_SECINFO, "cve", 0, 0);

      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM scap.cpes"
                   "  WHERE modification_time"
                   "        > coalesce (CAST ((SELECT value FROM meta"
                   "                           WHERE name"
                   "                                 = 'scap_check_time')"
                   "                          AS INTEGER),"
                   "                    0)"
                   "  AND creation_time"
                   "      <= coalesce (CAST ((SELECT value FROM meta"
                   "                          WHERE name"
                   "                                = 'scap_check_time')"
                   "                         AS INTEGER),"
                   "                   0));"))
        event (EVENT_UPDATED_SECINFO, "cpe", 0, 0);
    }
}

/**
 * @brief Check for updated CERT SecInfo after an update.
 */
static void
check_for_updated_cert ()
{
  if (manage_cert_loaded ())
    {
      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM cert.cert_bund_advs"
                   "  WHERE modification_time"
                   "        > coalesce (CAST ((SELECT value FROM meta"
                   "                           WHERE name"
                   "                                 = 'cert_check_time')"
                   "                          AS INTEGER),"
                   "                    0)"
                   "  AND creation_time"
                   "      <= coalesce (CAST ((SELECT value FROM meta"
                   "                          WHERE name"
                   "                                = 'cert_check_time')"
                   "                         AS INTEGER),"
                   "                   0));"))
        event (EVENT_UPDATED_SECINFO, "cert_bund_adv", 0, 0);

      if (sql_int ("SELECT EXISTS"
                   " (SELECT * FROM cert.dfn_cert_advs"
                   "  WHERE modification_time"
                   "        > coalesce (CAST ((SELECT value FROM meta"
                   "                           WHERE name"
                   "                                 = 'cert_check_time')"
                   "                          AS INTEGER),"
                   "                    0)"
                   "  AND creation_time"
                   "      <= coalesce (CAST ((SELECT value FROM meta"
                   "                          WHERE name"
                   "                                = 'cert_check_time')"
                   "                         AS INTEGER),"
                   "                   0));"))
        event (EVENT_UPDATED_SECINFO, "dfn_cert_adv", 0, 0);
    }
}

/**
 * @brief Check if any SecInfo alerts are due.
 */
void
check_alerts ()
{
  if (manage_scap_loaded ())
    {
      int max_time;

      max_time
       = sql_int ("SELECT %s"
                  "        ((SELECT max (modification_time) FROM scap.cves),"
                  "         (SELECT max (modification_time) FROM scap.cpes),"
                  "         (SELECT max (creation_time) FROM scap.cves),"
                  "         (SELECT max (creation_time) FROM scap.cpes));",
                  sql_greatest ());

      if (sql_int ("SELECT NOT EXISTS (SELECT * FROM meta"
                   "                   WHERE name = 'scap_check_time')"))
        sql ("INSERT INTO meta (name, value)"
             " VALUES ('scap_check_time', %i);",
             max_time);
      else if (sql_int ("SELECT value = '0' FROM meta"
                        " WHERE name = 'scap_check_time';"))
        sql ("UPDATE meta SET value = %i"
             " WHERE name = 'scap_check_time';",
             max_time);
      else
        {
          check_for_new_scap ();
          check_for_updated_scap ();
          sql ("UPDATE meta SET value = %i"
               " WHERE name = 'scap_check_time';",
               max_time);
        }
    }

  if (manage_cert_loaded ())
    {
      int max_time;

      max_time
       = sql_int ("SELECT"
                  " %s"
                  "  ((SELECT max (modification_time) FROM cert.cert_bund_advs),"
                  "   (SELECT max (modification_time) FROM cert.dfn_cert_advs),"
                  "   (SELECT max (creation_time) FROM cert.cert_bund_advs),"
                  "   (SELECT max (creation_time) FROM cert.dfn_cert_advs));",
                  sql_greatest ());

      if (sql_int ("SELECT NOT EXISTS (SELECT * FROM meta"
                   "                   WHERE name = 'cert_check_time')"))
        sql ("INSERT INTO meta (name, value)"
             " VALUES ('cert_check_time', %i);",
             max_time);
      else if (sql_int ("SELECT value = '0' FROM meta"
                        " WHERE name = 'cert_check_time';"))
        sql ("UPDATE meta SET value = %i"
             " WHERE name = 'cert_check_time';",
             max_time);
      else
        {
          check_for_new_cert ();
          check_for_updated_cert ();
          sql ("UPDATE meta SET value = %i"
               " WHERE name = 'cert_check_time';",
               max_time);
        }
    }
}
