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
