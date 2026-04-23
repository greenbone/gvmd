/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_schedules.h"
#include "manage.h" // for current_credentials
#include "manage_acl.h"
#include "manage_sql_permissions.h"
#include "manage_sql_resources.h"
#include "manage_sql_tags.h"

#include <libical/ical.h>

/**
 * @brief Create a schedule.
 *
 * @param[in]   name        Name of schedule.
 * @param[in]   comment     Comment on schedule.
 * @param[in]   ical_string iCalendar string.  Overrides first_time, period,
 *                           period_months, byday and duration.
 * @param[in]   zone        Timezone.
 * @param[out]  schedule    Created schedule.
 * @param[out]  error_out   Output for iCalendar errors and warnings.
 *
 * @return 0 success, 1 schedule exists already,
 *         3 error in iCal string, 4 error in timezone, 99 permission denied.
 */

int
create_schedule (const char* name, const char *comment,
                 const char *ical_string, const char* zone,
                 schedule_t *schedule, gchar **error_out)
{
  gchar *quoted_comment, *quoted_name, *quoted_timezone;
  gchar *insert_timezone;
  int byday_mask;
  icalcomponent *ical_component;
  icaltimezone *ical_timezone;
  gchar *quoted_ical;
  time_t first_time, period, period_months, duration;

  assert (current_credentials.uuid);
  assert (ical_string && strcmp (ical_string, ""));

  sql_begin_immediate ();

  if (acl_user_may ("create_schedule") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (resource_with_name_exists (name, "schedule", 0))
    {
      sql_rollback ();
      return 1;
    }

  quoted_name = sql_quote (name);

  if (zone && strcmp (zone, ""))
    insert_timezone = g_strdup (zone);
  else
    insert_timezone = sql_string ("SELECT timezone FROM users"
                                  " WHERE users.uuid = '%s';",
                                  current_credentials.uuid);

  if (insert_timezone == NULL)
    insert_timezone = g_strdup ("UTC");
  else
    {
      insert_timezone = g_strstrip (insert_timezone);
      if (strcmp (insert_timezone, "") == 0)
        {
          g_free (insert_timezone);
          insert_timezone = g_strdup ("UTC");
        }
    }

  ical_timezone = icalendar_timezone_from_string (insert_timezone);
  if (ical_timezone == NULL)
    {
      g_free (insert_timezone);
      return 4;
    }

  quoted_comment = sql_quote (comment ? comment : "");
  quoted_timezone = sql_quote (insert_timezone);

  ical_component = icalendar_from_string (ical_string, ical_timezone,
                                          error_out);
  if (ical_component == NULL)
    {
      g_free (quoted_name);
      g_free (quoted_comment);
      g_free (insert_timezone);
      g_free (quoted_timezone);
      return 3;
    }
  quoted_ical = sql_quote (icalcomponent_as_ical_string (ical_component));
  first_time = icalendar_first_time_from_vcalendar (ical_component,
                                                    ical_timezone);
  duration = icalendar_duration_from_vcalendar (ical_component);

  icalendar_approximate_rrule_from_vcalendar (ical_component,
                                              &period,
                                              &period_months,
                                              &byday_mask);

  sql ("INSERT INTO schedules"
       " (uuid, name, owner, comment, first_time, period, period_months,"
       "  byday, duration, timezone, icalendar,"
       "  creation_time, modification_time)"
       " VALUES"
       " (make_uuid (), '%s',"
       "  (SELECT id FROM users WHERE users.uuid = '%s'),"
       "  '%s', %i, %i, %i, %i, %i,"
       "  '%s', '%s',"
       "  m_now (), m_now ());",
       quoted_name, current_credentials.uuid, quoted_comment, first_time,
       period, period_months, byday_mask, duration, quoted_timezone,
       quoted_ical);

  if (schedule)
    *schedule = sql_last_insert_id ();

  g_free (quoted_name);
  g_free (quoted_comment);
  g_free (insert_timezone);
  g_free (quoted_timezone);
  g_free (quoted_ical);

  sql_commit ();

  return 0;
}

/**
 * @brief Create a schedule from an existing schedule.
 *
 * @param[in]  name          Name of new schedule. NULL to copy from existing.
 * @param[in]  comment       Comment on new schedule. NULL to copy from
 *                           existing.
 * @param[in]  schedule_id   UUID of existing schedule.
 * @param[out] new_schedule  New schedule.
 *
 * @return 0 success, 1 schedule exists already, 2 failed to find existing
 *         schedule, -1 error.
 */
int
copy_schedule (const char* name, const char* comment, const char *schedule_id,
               schedule_t* new_schedule)
{
  return copy_resource ("schedule", name, comment, schedule_id,
                        "first_time, period, period_months, byday, duration,"
                        " timezone, icalendar",
                        1, new_schedule, NULL);
}

/**
 * @brief Delete a schedule.
 *
 * @param[in]  schedule_id  Schedule.
 * @param[in]  ultimate     Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 fail because a task refers to the schedule,
 *         2 failed to find schedule, 99 permission denied, -1 error.
 */
int
delete_schedule (const char *schedule_id, int ultimate)
{
  schedule_t schedule = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_schedule") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_schedule_with_permission (schedule_id, &schedule, "delete_schedule"))
    {
      sql_rollback ();
      return -1;
    }

  if (schedule == 0)
    {
      if (find_trash ("schedule", schedule_id, &schedule))
        {
          sql_rollback ();
          return -1;
        }
      if (schedule == 0)
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
      if (sql_int ("SELECT count(*) FROM tasks"
                   " WHERE schedule = %llu"
                   " AND schedule_location = " G_STRINGIFY (LOCATION_TRASH) ";",
                   schedule))
        {
          sql_rollback ();
          return 1;
        }

      permissions_set_orphans ("schedule", schedule, LOCATION_TRASH);
      tags_remove_resource ("schedule", schedule, LOCATION_TRASH);

      sql ("DELETE FROM schedules_trash WHERE id = %llu;", schedule);
      sql_commit ();
      return 0;
    }

  if (ultimate == 0)
    {
      if (sql_int ("SELECT count(*) FROM tasks"
                   " WHERE schedule = %llu"
                   " AND schedule_location = " G_STRINGIFY (LOCATION_TABLE)
                   " AND hidden = 0;",
                   schedule))
        {
          sql_rollback ();
          return 1;
        }

      sql ("INSERT INTO schedules_trash"
           " (uuid, owner, name, comment, first_time, period, period_months,"
           "  byday, duration, timezone, creation_time,"
           "  modification_time, icalendar)"
           " SELECT uuid, owner, name, comment, first_time, period, period_months,"
           "        byday, duration, timezone, creation_time,"
           "        modification_time, icalendar"
           " FROM schedules WHERE id = %llu;",
           schedule);

      /* Update the location of the schedule in any trashcan tasks. */
      sql ("UPDATE tasks"
           " SET schedule = %llu,"
           "     schedule_location = " G_STRINGIFY (LOCATION_TRASH)
           " WHERE schedule = %llu"
           " AND schedule_location = " G_STRINGIFY (LOCATION_TABLE) ";",
           sql_last_insert_id (),
           schedule);

      permissions_set_locations ("schedule", schedule,
                                 sql_last_insert_id (),
                                 LOCATION_TRASH);
      tags_set_locations ("schedule", schedule,
                          sql_last_insert_id (),
                          LOCATION_TRASH);
    }
  else if (sql_int ("SELECT count(*) FROM tasks"
                    " WHERE schedule = %llu"
                    " AND schedule_location = " G_STRINGIFY (LOCATION_TABLE),
                    schedule))
    {
      sql_rollback ();
      return 1;
    }
  else
    {
      permissions_set_orphans ("schedule", schedule, LOCATION_TABLE);
      tags_remove_resource ("schedule", schedule, LOCATION_TABLE);
    }

  sql ("DELETE FROM schedules WHERE id = %llu;", schedule);

  sql_commit ();
  return 0;
}

/**
 * @brief Modify a schedule.
 *
 * @param[in]   schedule_id  UUID of schedule.
 * @param[in]   name         Name of schedule.
 * @param[in]   comment      Comment on schedule.
 * @param[in]   ical_string  iCalendar string.  Overrides first_time, period,
 *                           period_months, byday and duration.
 * @param[in]   zone         Timezone.
 * @param[out]  error_out    Output for iCalendar errors and warnings.
 *
 * @return 0 success, 1 failed to find schedule, 2 schedule with new name exists,
 *         3 error in type name, 4 schedule_id required,
 *         6 error in iCalendar, 7 error in zone,
 *         99 permission denied, -1 internal error.
 */
int
modify_schedule (const char *schedule_id, const char *name, const char *comment,
                 const char *ical_string, const char *zone, gchar **error_out)
{
  gchar *quoted_name, *quoted_comment, *quoted_timezone, *quoted_icalendar;
  icalcomponent *ical_component;
  icaltimezone *ical_timezone;
  schedule_t schedule;
  time_t new_next_time, ical_first_time, ical_duration;
  gchar *real_timezone;

  assert (ical_string && strcmp (ical_string, ""));

  if (schedule_id == NULL)
    return 4;

  sql_begin_immediate ();

  assert (current_credentials.uuid);

  if (acl_user_may ("modify_schedule") == 0)
    {
      sql_rollback ();
      return 99;
    }

  schedule = 0;
  if (find_schedule_with_permission (schedule_id, &schedule, "modify_schedule"))
    {
      sql_rollback ();
      return -1;
    }

  if (schedule == 0)
    {
      sql_rollback ();
      return 1;
    }

  /* Check whether a schedule with the same name exists already. */
  if (name)
    {
      if (resource_with_name_exists (name, "schedule", schedule))
        {
          sql_rollback ();
          return 2;
        }
      quoted_name = sql_quote (name);
    }
  else
    quoted_name = NULL;

  /* Update basic data */
  quoted_comment = comment ? sql_quote (comment) : NULL;

  if (zone == NULL)
    quoted_timezone = NULL;
  else
    {
      quoted_timezone = g_strstrip (sql_quote (zone));
      if (strcmp (quoted_timezone, "") == 0)
        {
          g_free (quoted_timezone);
          quoted_timezone = NULL;
        }
    }

  sql ("UPDATE schedules SET"
       " name = %s%s%s,"
       " comment = %s%s%s,"
       " timezone = %s%s%s"
       " WHERE id = %llu;",
       quoted_name ? "'" : "",
       quoted_name ? quoted_name : "name",
       quoted_name ? "'" : "",
       quoted_comment ? "'" : "",
       quoted_comment ? quoted_comment : "comment",
       quoted_comment ? "'" : "",
       quoted_timezone ? "'" : "",
       quoted_timezone ? quoted_timezone : "timezone",
       quoted_timezone ? "'" : "",
       schedule);

  real_timezone
    = sql_string ("SELECT timezone FROM schedules WHERE id = %llu;",
                  schedule);

  /* Update times */

  ical_timezone = icalendar_timezone_from_string (real_timezone);
  if (ical_timezone == NULL)
    {
      g_free (real_timezone);
      sql_rollback ();
      return 7;
    }

  ical_component = icalendar_from_string (ical_string, ical_timezone,
                                          error_out);
  if (ical_component == NULL)
    {
      g_free (real_timezone);
      sql_rollback ();
      return 6;
    }

  quoted_icalendar = sql_quote (icalcomponent_as_ical_string
                                  (ical_component));

  ical_first_time = icalendar_first_time_from_vcalendar (ical_component,
                                                         ical_timezone);
  ical_duration = icalendar_duration_from_vcalendar (ical_component);

  sql ("UPDATE schedules SET"
       " icalendar = '%s',"
       " first_time = %ld,"
       " period = 0,"
       " period_months = 0,"
       " byday = 0,"
       " duration = %d,"
       " modification_time = m_now ()"
       " WHERE id = %llu;",
       quoted_icalendar,
       ical_first_time,
       ical_duration,
       schedule);

  // Update scheduled next times for tasks

  new_next_time = icalendar_next_time_from_vcalendar (ical_component,
                                                      time(NULL),
                                                      real_timezone, 0);

  sql ("UPDATE tasks SET schedule_next_time = %ld"
       " WHERE schedule = %llu;",
       new_next_time,
       schedule);

  g_free (quoted_comment);
  g_free (quoted_name);
  g_free (quoted_timezone);
  g_free (quoted_icalendar);

  free (real_timezone);
  icalcomponent_free (ical_component);

  sql_commit ();

  return 0;
}

/**
 * @brief Return whether a schedule is in use by a task.
 *
 * @param[in]  schedule  Schedule.
 *
 * @return 1 if in use, else 0.
 */
int
schedule_in_use (schedule_t schedule)
{
  return !!sql_int ("SELECT count(*) FROM tasks WHERE schedule = %llu"
                    " AND hidden = 0;", schedule);
}

/**
 * @brief Return whether a trashcan schedule is in use by a task.
 *
 * @param[in]  schedule  schedule.
 *
 * @return 1 if in use, else 0.
 */
int
trash_schedule_in_use (schedule_t schedule)
{
  return !!sql_int ("SELECT count(*) FROM tasks"
                    " WHERE schedule = %llu"
                    " AND schedule_location = " G_STRINGIFY (LOCATION_TRASH),
                    schedule);
}

/**
 * @brief Return the UUID of a schedule.
 *
 * @param[in]  schedule  Schedule.
 *
 * @return Newly allocated UUID.
 */
char *
schedule_uuid (schedule_t schedule)
{
  return sql_string ("SELECT uuid FROM schedules WHERE id = %llu;",
                     schedule);
}

/**
 * @brief Return the UUID of a trash schedule.
 *
 * @param[in]  schedule  Schedule.
 *
 * @return Newly allocated UUID.
 */
char *
trash_schedule_uuid (schedule_t schedule)
{
  return sql_string ("SELECT uuid FROM schedules_trash WHERE id = %llu;",
                     schedule);
}

/**
 * @brief Return the name of a schedule.
 *
 * @param[in]  schedule  Schedule.
 *
 * @return Newly allocated name.
 */
char *
schedule_name (schedule_t schedule)
{
  return sql_string ("SELECT name FROM schedules WHERE id = %llu;",
                     schedule);
}

/**
 * @brief Return the name of a trash schedule.
 *
 * @param[in]  schedule  Schedule.
 *
 * @return Newly allocated name.
 */
char *
trash_schedule_name (schedule_t schedule)
{
  return sql_string ("SELECT name FROM schedules_trash WHERE id = %llu;",
                     schedule);
}

/**
 * @brief Return the period of a schedule.
 *
 * @param[in]  schedule  Schedule.
 *
 * @return Period in seconds.
 */
int
schedule_period (schedule_t schedule)
{
  return sql_int ("SELECT period FROM schedules WHERE id = %llu;",
                  schedule);
}

/**
 * @brief Return the duration of a schedule.
 *
 * @param[in]  schedule  Schedule.
 *
 * @return Duration in seconds.
 */
int
schedule_duration (schedule_t schedule)
{
  return sql_int ("SELECT duration FROM schedules WHERE id = %llu;",
                  schedule);
}

/**
 * @brief Return info about a schedule.
 *
 * @param[in]  schedule    Schedule.
 * @param[in]  trash       Whether to get schedule from trash.
 * @param[out] icalendar      iCalendar string.
 * @param[out] zone           Timezone string.
 *
 * @return 0 success, -1 error.
 */
int
schedule_info (schedule_t schedule, int trash, gchar **icalendar, gchar **zone)
{
  iterator_t schedules;

  init_iterator (&schedules,
                 "SELECT icalendar, timezone FROM schedules%s"
                 " WHERE id = %llu;",
                 trash ? "_trash" : "",
                 schedule);
  if (next (&schedules))
    {
      *icalendar = g_strdup (iterator_string (&schedules, 0));
      *zone = g_strdup (iterator_string (&schedules, 1));
      cleanup_iterator (&schedules);
      return 0;
    }
  cleanup_iterator (&schedules);
  return -1;
}

/**
 * @brief Find a schedule for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of schedule.
 * @param[out]  schedule    Schedule return, 0 if successfully failed to find schedule.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find schedule), TRUE on error.
 */
gboolean
find_schedule_with_permission (const char* uuid, schedule_t* schedule,
                             const char *permission)
{
  return find_resource_with_permission ("schedule", uuid, schedule, permission, 0);
}

/**
 * @brief Count the number of schedules.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of schedules filtered set.
 */
int
schedule_count (const get_data_t *get)
{
  static const char *filter_columns[] = SCHEDULE_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = SCHEDULE_ITERATOR_COLUMNS;
  static column_t trash_columns[] = SCHEDULE_ITERATOR_TRASH_COLUMNS;
  return count ("schedule", get, columns, trash_columns, filter_columns,
                0, 0, 0, TRUE);
}

/**
 * @brief Initialise a schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find filter, 2 failed to find"
 *         filter (filt_id), -1 error.
 */
int
init_schedule_iterator (iterator_t* iterator, get_data_t *get)
{
  static const char *filter_columns[] = SCHEDULE_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = SCHEDULE_ITERATOR_COLUMNS;
  static column_t trash_columns[] = SCHEDULE_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "schedule",
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
 * @brief Get the timezone from a schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Timezone, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (schedule_iterator_timezone, GET_ITERATOR_COLUMN_COUNT + 4);

/**
 * @brief Get the iCalendar string from a schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The iCalendar string or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (schedule_iterator_icalendar, GET_ITERATOR_COLUMN_COUNT + 5);

/**
 * @brief Initialise a task schedule iterator.
 *
 * Lock the database before initialising.
 *
 * @param[in]  iterator        Iterator.
 *
 * @return 0 success, 1 failed to get lock, -1 error.
 */
int
init_task_schedule_iterator (iterator_t* iterator)
{
  int ret;

  ret = sql_begin_immediate_giveup ();
  if (ret)
    return ret;

  init_iterator (iterator,
                 "SELECT tasks.id, tasks.uuid,"
                 " schedules.id, tasks.schedule_next_time,"
                 " schedules.icalendar, schedules.timezone,"
                 " schedules.duration,"
                 " users.uuid, users.name"
                 " FROM tasks, schedules, users"
                 " WHERE tasks.schedule = schedules.id"
                 " AND tasks.hidden = 0"
                 " AND (tasks.owner = (users.id))"
                 /* Sort by task and prefer owner of task or schedule as user */
                 " ORDER BY tasks.id,"
                 "          (users.id = tasks.owner) DESC,"
                 "          (users.id = schedules.owner) DESC;");

  return 0;
}

/**
 * @brief Cleanup a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
cleanup_task_schedule_iterator (iterator_t* iterator)
{
  cleanup_iterator (iterator);
  sql_commit ();
}

/**
 * @brief Get the task from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return task.
 */
task_t
task_schedule_iterator_task (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (task_t) iterator_int64 (iterator, 0);
}

/**
 * @brief Get the task UUID from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Task UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (task_schedule_iterator_task_uuid, 1);

/**
 * @brief Get the next time from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Next time.
 */
static time_t
task_schedule_iterator_next_time (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (time_t) iterator_int64 (iterator, 3);
}

/**
 * @brief Get the iCalendar string from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return period.
 */
DEF_ACCESS (task_schedule_iterator_icalendar, 4);

/**
 * @brief Get the timezone from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Timezone, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (task_schedule_iterator_timezone, 5);

/**
 * @brief Get the next time from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Next time.
 */
static time_t
task_schedule_iterator_duration (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (time_t) iterator_int64 (iterator, 6);
}

/**
 * @brief Get the task owner uuid from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Owner UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (task_schedule_iterator_owner_uuid, 7);

/**
 * @brief Get the task owner name from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Owner name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (task_schedule_iterator_owner_name, 8);

/**
 * @brief Get the start due state from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Start due flag.
 */
gboolean
task_schedule_iterator_start_due (iterator_t* iterator)
{
  task_status_t run_status;
  time_t start_time;

  if (iterator->done) return FALSE;

  if (task_schedule_iterator_next_time (iterator) == 0)
    return FALSE;

  run_status = task_run_status (task_schedule_iterator_task (iterator));
  start_time = task_schedule_iterator_next_time (iterator);

  if ((run_status == TASK_STATUS_DONE
       || run_status == TASK_STATUS_INTERRUPTED
       || run_status == TASK_STATUS_NEW
       || run_status == TASK_STATUS_STOPPED)
      && (start_time > 0)
      && (start_time <= time (NULL)))
    return TRUE;

  return FALSE;
}

/**
 * @brief Get a report's scheduled flag.
 *
 * @param[in]   report  Report.
 *
 * @return Scheduled flag.
 */
static int
report_scheduled (report_t report)
{
  return sql_int ("SELECT flags FROM reports WHERE id = %llu;",
                  report);
}

/**
 * @brief Get the stop due state from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Stop due flag.
 */
gboolean
task_schedule_iterator_stop_due (iterator_t* iterator)
{
  const char *icalendar, *zone;
  time_t duration;

  if (iterator->done) return FALSE;

  icalendar = task_schedule_iterator_icalendar (iterator);
  zone = task_schedule_iterator_timezone (iterator);
  duration = task_schedule_iterator_duration (iterator);

  if (duration)
    {
      report_t report;
      task_status_t run_status;

      report = task_running_report (task_schedule_iterator_task (iterator));
      if (report && (report_scheduled (report) == 0))
        return FALSE;

      run_status = task_run_status (task_schedule_iterator_task (iterator));

      if (run_status == TASK_STATUS_RUNNING
          || run_status == TASK_STATUS_REQUESTED
          || run_status == TASK_STATUS_QUEUED)
        {
          time_t now, start;

          now = time (NULL);

          start = icalendar_next_time_from_string (icalendar, time(NULL), zone,
                                                   -1);
          if ((start + duration) < now)
            return TRUE;
        }
    }

  return FALSE;
}

/**
 * @brief Get if schedule of task in iterator is timed out.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Whether task schedule is timed out.
 */
gboolean
task_schedule_iterator_timed_out (iterator_t* iterator)
{
  time_t schedule_timeout_secs;
  int duration;
  task_status_t run_status;
  time_t start_time, timeout_time;

  if (get_schedule_timeout () < 0)
    return FALSE;

  if (iterator->done) return FALSE;

  start_time = task_schedule_iterator_next_time (iterator);

  if (start_time == 0)
    return FALSE;

  schedule_timeout_secs = get_schedule_timeout () * 60;
  if (schedule_timeout_secs < SCHEDULE_TIMEOUT_MIN_SECS)
    schedule_timeout_secs = SCHEDULE_TIMEOUT_MIN_SECS;

  run_status = task_run_status (task_schedule_iterator_task (iterator));
  duration = task_schedule_iterator_duration (iterator);

  if (duration && (duration < schedule_timeout_secs))
    timeout_time = start_time + duration;
  else
    timeout_time = start_time + schedule_timeout_secs;

  if ((run_status == TASK_STATUS_DONE
       || run_status == TASK_STATUS_INTERRUPTED
       || run_status == TASK_STATUS_NEW
       || run_status == TASK_STATUS_STOPPED)
      && (timeout_time <= time (NULL)))
    return TRUE;

  return FALSE;
}

/**
 * @brief Initialise a schedule task iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  schedule  Schedule.
 */
void
init_schedule_task_iterator (iterator_t* iterator, schedule_t schedule)
{
  gchar *available, *with_clause;
  get_data_t get;
  array_t *permissions;

  assert (current_credentials.uuid);

  get.trash = 0;
  permissions = make_array ();
  array_add (permissions, g_strdup ("get_tasks"));
  available = acl_where_owned ("task", &get, 1, "any", 0, permissions, 0,
                               &with_clause);
  array_free (permissions);
  init_iterator (iterator,
                 "%s"
                 " SELECT id, uuid, name, %s FROM tasks"
                 " WHERE schedule = %llu AND hidden = 0"
                 " ORDER BY name ASC;",
                 with_clause ? with_clause : "",
                 available,
                 schedule,
                 current_credentials.uuid);
  g_free (with_clause);
  g_free (available);
}

/**
 * @brief Get the UUID from a schedule task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (schedule_task_iterator_uuid, 1);

/**
 * @brief Get the name from a schedule task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (schedule_task_iterator_name, 2);

/**
 * @brief Get the read permission status from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if may read, else 0.
 */
int
schedule_task_iterator_readable (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, 3);
}
