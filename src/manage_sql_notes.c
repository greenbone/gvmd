/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_notes.h"
#include "manage_acl.h"
#include "manage_sql_filters.h"
#include "manage_sql_permissions.h"
#include "manage_sql_resources.h"
#include "manage_sql_settings.h"
#include "manage_sql_tags.h"
#include "sql.h"

#include <ctype.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @file
 * @brief GVM management layer: Notes SQL
 *
 * The Notes SQL for the GVM management layer.
 */

/**
 * @brief Create a note.
 *
 * @param[in]  active      NULL or -1 on, 0 off, n on for n days.
 * @param[in]  nvt         OID of noted NVT.
 * @param[in]  text        Note text.
 * @param[in]  hosts       Hosts to apply note to, NULL for any host.
 * @param[in]  port        Port to apply note to, NULL for any port.
 * @param[in]  severity    Severity to apply note to, "" or NULL for any.
 * @param[in]  threat      Threat to apply note to, "" or NULL for any threat.
 *                         Only used if severity is "" or NULL.
 * @param[in]  task        Task to apply note to, 0 for any task.
 * @param[in]  result      Result to apply note to, 0 for any result.
 * @param[out] note        Created note.
 *
 * @return 0 success, 1 failed to find NVT, 2 invalid port, 99 permission
 *         denied, -1 error.
 */
int
create_note (const char* active, const char* nvt, const char* text,
             const char* hosts, const char* port, const char* severity,
             const char* threat, task_t task, result_t result, note_t *note)
{
  gchar *quoted_text, *quoted_hosts, *quoted_port, *quoted_severity;
  double severity_dbl;

  if (acl_user_may ("create_note") == 0)
    return 99;

  if (nvt == NULL)
    return -1;

  if (!nvt_exists (nvt))
    return 1;

  if (port && validate_results_port (port))
    return 2;

  if (text == NULL)
    return -1;

  if (threat
      && strcmp (threat, "Critical")
      && strcmp (threat, "High")
      && strcmp (threat, "Medium")
      && strcmp (threat, "Low")
      && strcmp (threat, "Log")
      && strcmp (threat, ""))
    return -1;

  quoted_text = sql_insert (text);
  quoted_hosts = sql_insert (hosts);
  quoted_port = sql_insert (port);

  severity_dbl = 0.0;
  if (severity != NULL && strcmp (severity, ""))
    {
      if (sscanf (severity, "%lf", &severity_dbl) != 1
          || ((severity_dbl < 0.0 || severity_dbl > 10.0)
              && severity_dbl != SEVERITY_LOG))
        return 3;
      quoted_severity = g_strdup_printf ("'%1.1f'", severity_dbl);
    }
  else if (threat != NULL && strcmp (threat, ""))
    {
      if (strcmp (threat, "Alarm") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "Critical") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "High") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "Medium") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "Low") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "Log") == 0)
        severity_dbl = SEVERITY_LOG;
      else
        return -1;

      quoted_severity = g_strdup_printf ("'%1.1f'", severity_dbl);
    }
  else
    quoted_severity = g_strdup ("NULL");

  sql ("INSERT INTO notes"
       " (uuid, owner, nvt, creation_time, modification_time, text, hosts,"
       "  port, severity, task, result, end_time)"
       " VALUES"
       " (make_uuid (), (SELECT id FROM users WHERE users.uuid = '%s'),"
       "  '%s', %i, %i, %s, %s, %s, %s, %llu, %llu, %i);",
       current_credentials.uuid,
       nvt,
       time (NULL),
       time (NULL),
       quoted_text,
       quoted_hosts,
       quoted_port,
       quoted_severity,
       task,
       result,
       (active == NULL || (strcmp (active, "-1") == 0))
         ? 0
         : (strcmp (active, "0")
             ? (time (NULL) + (atoi (active) * 60 * 60 * 24))
             : 1));

  g_free (quoted_text);
  g_free (quoted_hosts);
  g_free (quoted_port);
  g_free (quoted_severity);

  if (note)
    *note = sql_last_insert_id ();

  return 0;
}

/**
 * @brief Create a note from an existing note.
 *
 * @param[in]  note_id   UUID of existing note.
 * @param[out] new_note  New note.
 *
 * @return 0 success, 1 note exists already, 2 failed to find existing
 *         note, -1 error.
 */
int
copy_note (const char *note_id, note_t* new_note)
{
  return copy_resource ("note", NULL, NULL, note_id,
                        "nvt, text, hosts, port, severity, task, result,"
                        "end_time",
                        1, new_note, NULL);
}

/**
 * @brief Delete a note.
 *
 * @param[in]  note_id    UUID of note.
 * @param[in]  ultimate   Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 2 failed to find note, 99 permission denied, -1 error.
 */
int
delete_note (const char *note_id, int ultimate)
{
  note_t note = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_note") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_note_with_permission (note_id, &note, "delete_note"))
    {
      sql_rollback ();
      return -1;
    }

  if (note == 0)
    {
      if (find_trash ("note", note_id, &note))
        {
          sql_rollback ();
          return -1;
        }
      if (note == 0)
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

      permissions_set_orphans ("note", note, LOCATION_TRASH);
      tags_remove_resource ("note", note, LOCATION_TRASH);

      sql ("DELETE FROM notes_trash WHERE id = %llu;", note);
      sql_commit ();
      return 0;
    }

  if (ultimate == 0)
    {
      sql ("INSERT INTO notes_trash"
           " (uuid, owner, nvt, creation_time, modification_time, text, hosts,"
           "  port, severity, task, result, end_time)"
           " SELECT uuid, owner, nvt, creation_time, modification_time, text,"
           "        hosts, port, severity, task, result, end_time"
           " FROM notes WHERE id = %llu;",
           note);

      permissions_set_locations ("note", note,
                                 sql_last_insert_id (),
                                 LOCATION_TRASH);
      tags_set_locations ("note", note,
                          sql_last_insert_id (),
                          LOCATION_TRASH);
    }
  else
    {
      permissions_set_orphans ("note", note, LOCATION_TABLE);
      tags_remove_resource ("note", note, LOCATION_TABLE);
    }

  sql ("DELETE FROM notes WHERE id = %llu;", note);

  sql_commit ();
  return 0;
}

/**
 * @brief Return the UUID of a note.
 *
 * @param[in]   note  Note.
 * @param[out]  id    Pointer to a newly allocated string.
 *
 * @return 0.
 */
int
note_uuid (note_t note, char ** id)
{
  *id = sql_string ("SELECT uuid FROM notes WHERE id = %llu;",
                    note);
  return 0;
}

/**
 * @brief Modify a note.
 *
 * @param[in]  note_id     Note.
 * @param[in]  active      NULL or -2 leave as is, -1 on, 0 off, n on for n
 *                         days.
 * @param[in]  nvt         OID of noted NVT.
 * @param[in]  text        Note text.
 * @param[in]  hosts       Hosts to apply note to, NULL for any host.
 * @param[in]  port        Port to apply note to, NULL for any port.
 * @param[in]  severity    Severity to apply note to, "" or NULL for any.
 * @param[in]  threat      Threat to apply note to, "" or NULL for any threat.
 *                         Only used if severity is "" or NULL.
 * @param[in]  task_id     Task to apply note to, NULL for any task.
 * @param[in]  result_id   Result to apply note to, 0 for any result.
 *
 * @return 0 success, -1 error, 1 syntax error in active, 2 invalid port,
 *         3 invalid severity, 4 failed to find NVT, 5 failed to find note,
 *         6 failed to find task, 7 failed to find result.
 */
int
modify_note (const gchar *note_id, const char *active, const char *nvt,
             const char *text, const char *hosts, const char *port,
             const char *severity, const char *threat, const gchar *task_id,
             const gchar *result_id)
{
  gchar *quoted_text, *quoted_hosts, *quoted_port, *quoted_severity;
  double severity_dbl;
  gchar *quoted_nvt;
  note_t note;
  task_t task;
  result_t result;

  note = 0;
  if (find_note_with_permission (note_id, &note, "modify_note"))
    return -1;
  else if (note == 0)
    return 5;

  task = 0;
  if (task_id)
    {
      if (find_task_with_permission (task_id, &task, NULL))
        return -1;
      if (task == 0)
        {
          if (find_trash_task_with_permission (task_id, &task, NULL))
            return -1;
          if (task == 0)
            return 6;
        }
    }

  result = 0;
  if (result_id)
    {
      if (find_result_with_permission (result_id, &result, NULL))
        return -1;
      if (result == 0)
        return 7;
    }

  if (text == NULL)
    return -1;

  if (nvt && !nvt_exists (nvt))
    return 4;

  if (threat
      && strcmp (threat, "Critical")
      && strcmp (threat, "High")
      && strcmp (threat, "Medium")
      && strcmp (threat, "Low")
      && strcmp (threat, "Log")
      && strcmp (threat, "Alarm")
      && strcmp (threat, ""))
    return -1;

  if (port && validate_results_port (port))
    return 2;

  quoted_text = sql_insert (text);
  quoted_hosts = sql_insert (hosts);
  quoted_port = sql_insert (port);
  quoted_nvt = sql_insert (nvt);

  severity_dbl = 0.0;
  if (severity != NULL && strcmp (severity, ""))
    {
      if (sscanf (severity, "%lf", &severity_dbl) != 1
          || ((severity_dbl < 0.0 || severity_dbl > 10.0)
              && severity_dbl != SEVERITY_LOG))
        return 3;
      quoted_severity = g_strdup_printf ("'%1.1f'", severity_dbl);
    }
  else if (threat != NULL && strcmp (threat, ""))
    {
      if (strcmp (threat, "Alarm") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "Critical") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "High") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "Medium") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "Low") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "Log") == 0)
        severity_dbl = SEVERITY_LOG;
      else
        return -1;

      quoted_severity = g_strdup_printf ("'%1.1f'", severity_dbl);
    }
  else
    quoted_severity = g_strdup ("NULL");

  if ((active == NULL) || (strcmp (active, "-2") == 0))
    sql ("UPDATE notes SET"
         " modification_time = %i,"
         " text = %s,"
         " hosts = %s,"
         " port = %s,"
         " severity = %s,"
         " %s%s%s"
         " task = %llu,"
         " result = %llu"
         " WHERE id = %llu;",
         time (NULL),
         quoted_text,
         quoted_hosts,
         quoted_port,
         quoted_severity,
         nvt ? "nvt = " : "",
         nvt ? quoted_nvt : "",
         nvt ? "," : "",
         task,
         result,
         note);
  else
    {
      const char *point;
      point = active;
      if (strcmp (point, "-1"))
        {
          while (*point && isdigit (*point)) point++;
          if (*point)
            return 1;
        }
      sql ("UPDATE notes SET"
           " end_time = %i,"
           " modification_time = %i,"
           " text = %s,"
           " hosts = %s,"
           " port = %s,"
           " severity = %s,"
           "%s%s%s"
           " task = %llu,"
           " result = %llu"
           " WHERE id = %llu;",
           (strcmp (active, "-1")
             ? (strcmp (active, "0")
                 ? (time (NULL) + atoi (active) * 60 * 60 * 24)
                 : 1)
             : 0),
           time (NULL),
           quoted_text,
           quoted_hosts,
           quoted_port,
           quoted_severity,
           nvt ? "nvt = " : "",
           nvt ? quoted_nvt : "",
           nvt ? "," : "",
           task,
           result,
           note);
    }

  g_free (quoted_text);
  g_free (quoted_hosts);
  g_free (quoted_port);
  g_free (quoted_severity);
  g_free (quoted_nvt);

  return 0;
}

/**
 * @brief Count number of notes.
 *
 * @param[in]  get         GET params.
 * @param[in]  result      Result to limit notes to, 0 for all.
 * @param[in]  task        If result is > 0, task whose notes on result to
 *                         include, otherwise task to limit notes to.  0 for
 *                         all tasks.
 * @param[in]  nvt         NVT to limit notes to, 0 for all.
 *
 * @return Total number of notes in filtered set.
 */
int
note_count (const get_data_t *get, nvt_t nvt, result_t result, task_t task)
{
  static const char *filter_columns[] = NOTE_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = NOTE_ITERATOR_COLUMNS;
  static column_t trash_columns[] = NOTE_ITERATOR_TRASH_COLUMNS;
  gchar *result_clause, *filter, *task_id;
  int ret;

  /* Treat the "task_id" filter keyword as if the task was given in "task". */

  if (get->filt_id && strcmp (get->filt_id, FILT_ID_NONE))
    {
      filter = filter_term (get->filt_id);
      if (filter == NULL)
        return 2;
    }
  else
    filter = NULL;

  task_id = filter_term_value (filter ? filter : get->filter, "task_id");

  g_free (filter);

  if (task_id)
    {
      find_task_with_permission (task_id, &task, "get_tasks");
      g_free (task_id);
    }

  if (result)
    {
      gchar *severity_sql;

      if (setting_dynamic_severity_int ())
        severity_sql = g_strdup_printf ("(SELECT CASE"
                                        " WHEN results.severity"
                                        "      > " G_STRINGIFY (SEVERITY_LOG)
                                        " THEN CAST (nvts.cvss_base AS real)"
                                        " ELSE results.severity END"
                                        " FROM results, nvts"
                                        " WHERE (nvts.oid = results.nvt)"
                                        "   AND (results.id = %llu))",
                                        result);
      else
        severity_sql = g_strdup_printf ("(SELECT results.severity"
                                        " FROM results"
                                        " WHERE results.id = %llu)",
                                        result);

      result_clause = g_strdup_printf (" AND"
                                       " (result = %llu"
                                       "  OR (result = 0 AND nvt ="
                                       "      (SELECT results.nvt FROM results"
                                       "       WHERE results.id = %llu)))"
                                       " AND (hosts is NULL"
                                       "      OR hosts = ''"
                                       "      OR hosts_contains (hosts,"
                                       "      (SELECT results.host FROM results"
                                       "       WHERE results.id = %llu)))"
                                       " AND (port is NULL"
                                       "      OR port = ''"
                                       "      OR port ="
                                       "      (SELECT results.port FROM results"
                                       "       WHERE results.id = %llu))"
                                       " AND (severity_matches_ov (%s,"
                                       "                           severity))"
                                       " AND (task = 0 OR task = %llu)",
                                       result,
                                       result,
                                       result,
                                       result,
                                       severity_sql,
                                       task);
      g_free (severity_sql);
    }
  else if (task)
    {
      result_clause = g_strdup_printf
                       (" AND (notes.task = %llu OR notes.task = 0)"
                        " AND nvt IN"
                        " (SELECT DISTINCT nvt FROM results"
                        "  WHERE results.task = %llu)"
                        " AND (notes.result = 0"
                        "      OR (SELECT task FROM results"
                        "          WHERE results.id = notes.result)"
                        "         = %llu)",
                        task,
                        task,
                        task);
    }
  else if (nvt)
    {
      result_clause = g_strdup_printf
                       (" AND (notes.nvt = (SELECT oid FROM nvts"
                        "                   WHERE nvts.id = %llu))",
                        nvt);
    }
  else
    result_clause = NULL;

  ret = count ("note",
               get,
               columns,
               trash_columns,
               filter_columns,
               task || nvt,
               NULL,
               result_clause,
               TRUE);

  g_free (result_clause);

  return ret;
}

/**
 * @brief Initialise a note iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 * @param[in]  result      Result to limit notes to, 0 for all.
 * @param[in]  task        If result is > 0, task whose notes on result to
 *                         include, otherwise task to limit notes to.  0 for
 *                         all tasks.
 * @param[in]  nvt         NVT to limit notes to, 0 for all.
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_note_iterator (iterator_t* iterator, const get_data_t *get, nvt_t nvt,
                    result_t result, task_t task)
{
  static const char *filter_columns[] = NOTE_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = NOTE_ITERATOR_COLUMNS;
  static column_t trash_columns[] = NOTE_ITERATOR_TRASH_COLUMNS;
  gchar *result_clause, *filter, *task_id;
  int ret;

  assert (current_credentials.uuid);
  assert ((nvt && get->id) == 0);
  assert ((task && get->id) == 0);

  assert (result ? nvt == 0 : 1);
  assert (task ? nvt == 0 : 1);

  /* Treat the "task_id" filter keyword as if the task was given in "task". */

  if (get->filt_id && strcmp (get->filt_id, FILT_ID_NONE))
    {
      filter = filter_term (get->filt_id);
      if (filter == NULL)
        return 2;
    }
  else
    filter = NULL;

  task_id = filter_term_value (filter ? filter : get->filter, "task_id");

  g_free (filter);

  if (task_id)
    {
      find_task_with_permission (task_id, &task, "get_tasks");
      g_free (task_id);
    }

  if (result)
    {
      gchar *severity_sql;

      if (setting_dynamic_severity_int ())
        severity_sql = g_strdup_printf ("(SELECT CASE"
                                        " WHEN results.severity"
                                        "      > " G_STRINGIFY (SEVERITY_LOG)
                                        " THEN CAST (nvts.cvss_base AS real)"
                                        " ELSE results.severity END"
                                        " FROM results, nvts"
                                        " WHERE (nvts.oid = results.nvt)"
                                        "   AND (results.id = %llu))",
                                        result);
      else
        severity_sql = g_strdup_printf ("(SELECT results.severity"
                                        " FROM results"
                                        " WHERE results.id = %llu)",
                                        result);

      result_clause = g_strdup_printf (" AND"
                                       " (result = %llu"
                                       "  OR (result = 0 AND nvt ="
                                       "      (SELECT results.nvt FROM results"
                                       "       WHERE results.id = %llu)))"
                                       " AND (hosts is NULL"
                                       "      OR hosts = ''"
                                       "      OR hosts_contains (hosts,"
                                       "      (SELECT results.host FROM results"
                                       "       WHERE results.id = %llu)))"
                                       " AND (port is NULL"
                                       "      OR port = ''"
                                       "      OR port ="
                                       "      (SELECT results.port FROM results"
                                       "       WHERE results.id = %llu))"
                                       " AND (severity_matches_ov (%s,"
                                       "                           severity))"
                                       " AND (task = 0 OR task = %llu)",
                                       result,
                                       result,
                                       result,
                                       result,
                                       severity_sql,
                                       task);

      g_free (severity_sql);
    }
  else if (task)
    {
      result_clause = g_strdup_printf
                       (" AND (notes.task = %llu OR notes.task = 0)"
                        " AND nvt IN (SELECT DISTINCT nvt FROM results"
                        "             WHERE results.task = %llu)"
                        " AND (notes.result = 0"
                        "      OR (SELECT task FROM results"
                        "          WHERE results.id = notes.result)"
                        "         = %llu)",
                        task,
                        task,
                        task);
    }
  else if (nvt)
    {
      result_clause = g_strdup_printf
                       (" AND (notes.nvt = (SELECT oid FROM nvts"
                        "                   WHERE nvts.id = %llu))",
                        nvt);
    }
  else
    result_clause = NULL;

  ret = init_get_iterator (iterator,
                           "note",
                           get,
                           columns,
                           trash_columns,
                           filter_columns,
                           task || nvt,
                           NULL,
                           result_clause,
                           TRUE);

  g_free (result_clause);

  return ret;
}

/**
 * @brief Initialise a note iterator not limited to result, task or NVT.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_note_iterator_all (iterator_t* iterator, get_data_t *get)
{
  return init_note_iterator (iterator, get, 0, 0, 0);
}

/**
 * @brief Get the NVT OID from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT OID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (note_iterator_nvt_oid, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the text from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Text, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (note_iterator_text, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the hosts from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Hosts, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (note_iterator_hosts, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the port from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Port, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (note_iterator_port, GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Get the task from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The task associated with the note, or 0 on error.
 */
task_t
note_iterator_task (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (task_t) iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 4);
}

/**
 * @brief Get the result from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The result associated with the note, or 0 on error.
 */
result_t
note_iterator_result (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (result_t) iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 5);
}

/**
 * @brief Get the end time from an note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Time until which note applies.  0 for always.  1 means the
 *         note has been explicitly turned off.
 */
time_t
note_iterator_end_time (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (time_t) iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 6);
  return ret;
}

/**
 * @brief Get the active status from an note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if active, else 0.
 */
int
note_iterator_active (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 7);
  return ret;
}

/**
 * @brief Get the NVT name from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (note_iterator_nvt_name, GET_ITERATOR_COLUMN_COUNT + 8);

/**
 * @brief Get the NVT type from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT type, or NULL.  Static string.
 */
const char *
note_iterator_nvt_type (iterator_t *iterator)
{
  const char *oid;

  oid = note_iterator_nvt_oid (iterator);
  if (oid == NULL)
    return NULL;

  if (g_str_has_prefix (oid, "CVE-"))
    return "cve";

  return "nvt";
}

/**
 * @brief Get the severity from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The severity to apply the note to, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (note_iterator_severity, GET_ITERATOR_COLUMN_COUNT + 12);
