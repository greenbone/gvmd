/* Copyright (C) 2013-2018 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file  manage_migrators.c
 * @brief The Greenbone Vulnerability Manager DB Migrators file.
 *
 * This file defines the functions used by the manager to migrate the DB to the
 * newest version.
 */

/**
 * @section procedure_writing_migrator Procedure for writing a migrator
 *
 * Every change that affects the database schema or the format of the data in
 * the database must have a migrator so that someone using an older version of
 * the database can update to the newer version.
 *
 * Simply adding a new table to the database is, however, OK.  At startup, the
 * manager will automatically add a table if it is missing from the database.
 *
 *  - Ensure that the ChangeLog notes the changes to the database and
 *    the increase of GVMD_DATABASE_VERSION, with an entry like
 *
 *        * CMakeLists.txt (GVMD_DATABASE_VERSION): Increase to 6, for...
 *
 *        * src/manage_sql.c (create_tables): Add new table...
 *
 *  - Add the migrator function in the style of the others.  In particular,
 *    the function must check the version, do the modification and then set
 *    the new version, all inside an exclusive transaction.  Use the generic
 *    iterator (init_iterator, iterator_string, iterator_int64...) because the
 *    specialised iterators (like init_target_iterator) can change behaviour
 *    across Manager SVN versions.  Use copies of any other "manage" interfaces,
 *    for example update_all_config_caches, as these may also change in later
 *    versions of the Manager.
 *
 *  - Remember to ensure that tables exist in the migrator before the migrator
 *    modifies them.  If a migrator modifies a table then the table must either
 *    have existed in database version 0 (listed below), or some earlier
 *    migrator must have added the table, or the migrator must add the table
 *    (using the original schema of the table).
 *
 *  - Add the migrator to the database_migrators array.
 *
 *  - Test that everything still works for a database that has been migrated
 *    from the previous version.
 *
 *  - Test that everything still works for a database that has been migrated
 *    from version 0.
 *
 *  - Commit with a ChangeLog heading like
 *
 *        Add database migration from version 5 to 6.
 *
 * SQL that created database version 0:
 *
 *     CREATE TABLE IF NOT EXISTS config_preferences
 *       (config INTEGER, type, name, value);
 *
 *     CREATE TABLE IF NOT EXISTS configs
 *       (name UNIQUE, nvt_selector, comment, family_count INTEGER,
 *        nvt_count INTEGER, families_growing INTEGER, nvts_growing INTEGER);
 *
 *     CREATE TABLE IF NOT EXISTS meta
 *       (name UNIQUE, value);
 *
 *     CREATE TABLE IF NOT EXISTS nvt_selectors
 *       (name, exclude INTEGER, type INTEGER, family_or_nvt);
 *
 *     CREATE TABLE IF NOT EXISTS nvts
 *       (oid, version, name, summary, description, copyright, cve, bid, xref,
 *        tag, sign_key_ids, category, family);
 *
 *     CREATE TABLE IF NOT EXISTS report_hosts
 *       (report INTEGER, host, start_time, end_time, attack_state,
 *        current_port, max_port);
 *
 *     CREATE TABLE IF NOT EXISTS report_results
 *       (report INTEGER, result INTEGER);
 *
 *     CREATE TABLE IF NOT EXISTS reports
 *       (uuid, hidden INTEGER, task INTEGER, date INTEGER, start_time,
 *        end_time, nbefile, comment);
 *
 *     CREATE TABLE IF NOT EXISTS results
 *       (task INTEGER, subnet, host, port, nvt, type, description);
 *
 *     CREATE TABLE IF NOT EXISTS targets
 *       (name, hosts, comment);
 *
 *     CREATE TABLE IF NOT EXISTS tasks
 *       (uuid, name, hidden INTEGER, time, comment, description, owner,
 *        run_status, start_time, end_time, config, target);
 *
 *     CREATE TABLE IF NOT EXISTS users
 *       (name UNIQUE, password);
 */

/* time.h in glibc2 needs this for strptime. */
#define _XOPEN_SOURCE

#include <assert.h>
#include <errno.h>
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <time.h>
#ifdef __FreeBSD__
#include <sys/wait.h>
#endif
#include "manage_sql.h"
#include "sql.h"
#include "utils.h"

#include <ctype.h>
#include <dirent.h>
#include <gvm/base/logging.h>
#include <gvm/util/fileutils.h>
#include <gvm/util/uuidutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md   main"

/* Headers from backend specific manage_xxx.c file. */

void
manage_create_result_indexes ();

/* Types. */

/**
 * @brief A migrator.
 */
typedef struct
{
  int version;        ///< Version that the migrator produces.
  int (*function) (); ///< Function that does the migration.  NULL if too hard.
} migrator_t;

/* Functions. */

/** @todo May be better ensure a ROLLBACK when functions like "sql" fail.
 *
 * Currently the SQL functions abort on failure.  This a general problem,
 * not just for migrators, so perhaps the SQL interface should keep
 * track of the transaction, and rollback before aborting. */

/**
 * @brief Permission SQL for migrate_150_to_151.
 *
 * @param[in]  name  Name.
 * @param[in]  role  Role.
 */
static void
insert_permission (const char *name, const char *role)
{
  sql ("INSERT INTO permissions"
       " (uuid, owner, name, comment, resource_type, resource, resource_uuid,"
       "  resource_location, subject_type, subject, subject_location,"
       "  creation_time, modification_time)"
       " VALUES"
       "  (make_uuid (), NULL, '%s', '', '', 0, '', %d, 'role',"
       "   (SELECT id FROM roles WHERE uuid = '%s'), %d, m_now (), m_now ());",
       name,
       LOCATION_TABLE,
       role,
       LOCATION_TABLE);
}

/**
 * @brief Migrate the database from version 184 to version 185.
 *
 * @return 0 success, -1 error.
 */
int
migrate_184_to_185 ()
{
  iterator_t fkeys;

  sql_begin_immediate ();

  /* Ensure that the database is currently version 184. */

  if (manage_db_version () != 184)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Add missing scanner_location for configs in trashcan */

  sql ("ALTER TABLE configs_trash ADD COLUMN scanner_location INTEGER;");
  sql ("UPDATE configs_trash"
       "   SET scanner_location = " G_STRINGIFY (LOCATION_TABLE));

  /* Remove the foreign key constraint in Postgres */
  init_iterator (&fkeys,
                 "SELECT ccu.constraint_name"
                 "  FROM information_schema.constraint_column_usage AS ccu"
                 "  JOIN information_schema.table_constraints AS tc"
                 "    ON tc.constraint_name = ccu.constraint_name"
                 " WHERE tc.table_name = 'configs_trash'"
                 "  AND tc.constraint_type = 'FOREIGN KEY'"
                 "  AND ccu.table_name = 'scanners';");
  while (next (&fkeys))
    {
      const char *constraint_name;
      constraint_name = iterator_string (&fkeys, 0);
      sql ("ALTER TABLE configs_trash DROP constraint %s", constraint_name);
    }

  /* Set the database version to 185. */

  set_db_version (185);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 185 to version 186.
 *
 * @return 0 success, -1 error.
 */
int
migrate_185_to_186 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 185. */

  if (manage_db_version () != 185)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Ensure resource type of permission is credentials and not lsc_credentials.
   * Should have been done in migrate_153_to_154. */

  sql ("UPDATE permissions SET resource_type = 'credential'"
       " WHERE resource_type = 'lsc_credential';");

  sql ("UPDATE permissions_trash SET resource_type = 'credential'"
       " WHERE resource_type = 'lsc_credential';");

  /* Set the database version to 186. */

  set_db_version (186);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 186 to version 187.
 *
 * @return 0 success, -1 error.
 */
int
migrate_186_to_187 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 186. */

  if (manage_db_version () != 186)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Alerts tables got "active" columns. */

  sql ("ALTER TABLE alerts ADD COLUMN active INTEGER;");
  sql ("UPDATE alerts SET active = 1;");

  sql ("ALTER TABLE alerts_trash ADD COLUMN active INTEGER;");
  sql ("UPDATE alerts_trash SET active = 1;");

  /* Set the database version to 187. */

  set_db_version (187);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 187 to version 188.
 *
 * @return 0 success, -1 error.
 */
int
migrate_187_to_188 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 187. */

  if (manage_db_version () != 187)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Schedules tables got "byday" column. */

  sql ("ALTER TABLE schedules ADD COLUMN byday INTEGER;");
  sql ("UPDATE schedules SET byday = 0;");

  sql ("ALTER TABLE schedules_trash ADD COLUMN byday INTEGER;");
  sql ("UPDATE schedules_trash SET byday = 0;");

  /* Set the database version to 188. */

  set_db_version (188);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 188 to version 189.
 *
 * @return 0 success, -1 error.
 */
int
migrate_188_to_189 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 188. */

  if (manage_db_version () != 188)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Table result_nvts was added, with links in results and overrides. */

  sql ("CREATE TABLE result_nvts (id SERIAL PRIMARY KEY,"
       "                          nvt text UNIQUE NOT NULL);");

  sql ("INSERT INTO result_nvts (nvt)"
       " SELECT DISTINCT nvt"
       " FROM (SELECT DISTINCT nvt FROM results"
       "       UNION SELECT DISTINCT nvt FROM overrides"
       "       UNION SELECT DISTINCT nvt FROM overrides_trash)"
       "      AS sub;");

  sql ("CREATE TABLE IF NOT EXISTS results_188"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  task integer REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  host text,"
       "  port text,"
       "  nvt text,"
       "  result_nvt integer," // REFERENCES result_nvts (id),"
       "  type text,"
       "  description text,"
       "  report integer REFERENCES reports (id) ON DELETE RESTRICT,"
       "  nvt_version text,"
       "  severity real,"
       "  qod integer,"
       "  qod_type text,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  date integer);");

  sql ("INSERT INTO results_188"
       " (id, uuid, task, host, port, nvt, result_nvt, type, description,"
       "  report, nvt_version, severity, qod, qod_type, owner, date)"
       " SELECT id, uuid, task, host, port, nvt,"
       "           (SELECT id FROM result_nvts"
       "            WHERE result_nvts.nvt = results.nvt),"
       "           type, description, report, nvt_version,"
       "           severity, qod, qod_type, owner, date"
       "    FROM results;");

  /* This also removes indexes. */
  sql ("DROP TABLE results CASCADE;");
  sql ("ALTER TABLE results_188 RENAME TO results;");

  /* Ensure result indexes exist, for the SQL in the next migrator. */
  manage_create_result_indexes ();

  sql ("ALTER TABLE overrides ADD COLUMN result_nvt integer;");

  sql ("UPDATE overrides"
       " SET result_nvt = (SELECT id FROM result_nvts"
       "                   WHERE result_nvts.nvt = overrides.nvt)"
       " WHERE nvt IS NOT NULL;");

  sql ("ALTER TABLE overrides_trash ADD COLUMN result_nvt integer;");

  sql ("UPDATE overrides_trash"
       " SET result_nvt = (SELECT id FROM result_nvts"
       "                   WHERE result_nvts.nvt = overrides_trash.nvt)"
       " WHERE nvt IS NOT NULL;");

  /* Set the database version to 189. */

  set_db_version (189);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 189 to version 190.
 *
 * @return 0 success, -1 error.
 */
int
migrate_189_to_190 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 189. */

  if (manage_db_version () != 189)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Table result_nvts_reports was added, with an index. */

  sql ("CREATE TABLE result_nvt_reports (result_nvt INTEGER, report INTEGER);");

  sql ("INSERT INTO result_nvt_reports (result_nvt, report)"
       " SELECT DISTINCT result_nvts.id, results.report"
       " FROM result_nvts, results"
       " WHERE result_nvts.id = results.result_nvt;");

  sql ("CREATE INDEX result_nvt_reports_by_report"
       " ON result_nvt_reports (report);");

  /* Set the database version to 190. */

  set_db_version (190);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 190 to version 191.
 *
 * @return 0 success, -1 error.
 */
int
migrate_190_to_191 ()
{
  iterator_t schedule_iter;
  schedule_t schedule;
  time_t first_time, period, period_months, duration;
  int byday;
  const char *zone;
  icalcomponent *ical_component;
  gchar *quoted_ical;

  sql_begin_immediate ();

  /* Ensure that the database is currently version 190. */

  if (manage_db_version () != 190)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Add the column "icalendar" to the schedules tables. */

  sql ("ALTER TABLE schedules ADD COLUMN icalendar text;");

  sql ("ALTER TABLE schedules_trash ADD COLUMN icalendar text;");

  /* Calculate iCalendar strings for regular schedules table */
  init_iterator (&schedule_iter,
                 "SELECT id, first_time, period, period_months, duration,"
                 " byday, timezone"
                 " FROM schedules");

  while (next (&schedule_iter))
    {
      schedule = iterator_int64 (&schedule_iter, 0);
      first_time = (time_t) iterator_int64 (&schedule_iter, 1);
      period = (time_t) iterator_int64 (&schedule_iter, 2);
      period_months = (time_t) iterator_int64 (&schedule_iter, 3);
      duration = (time_t) iterator_int64 (&schedule_iter, 4);
      byday = iterator_int (&schedule_iter, 5);
      zone = iterator_string (&schedule_iter, 6);

      ical_component = icalendar_from_old_schedule_data (
        first_time, period, period_months, duration, byday, zone);
      quoted_ical = sql_quote (icalcomponent_as_ical_string (ical_component));

      g_debug ("%s: schedule %llu - first: %s (%s), period: %ld,"
               " period_months: %ld, duration: %ld - byday: %d\n"
               "generated iCalendar:\n%s",
               __FUNCTION__,
               schedule,
               iso_time_tz (&first_time, zone, NULL),
               zone,
               period,
               period_months,
               duration,
               byday,
               quoted_ical);

      sql ("UPDATE schedules SET icalendar = '%s' WHERE id = %llu",
           quoted_ical,
           schedule);

      icalcomponent_free (ical_component);
      g_free (quoted_ical);
    }

  cleanup_iterator (&schedule_iter);

  /* Calculate iCalendar strings for schedules_trash table */
  init_iterator (&schedule_iter,
                 "SELECT id, first_time, period, period_months, duration,"
                 " byday, timezone"
                 " FROM schedules_trash");

  while (next (&schedule_iter))
    {
      schedule = iterator_int64 (&schedule_iter, 0);
      first_time = (time_t) iterator_int64 (&schedule_iter, 1);
      period = (time_t) iterator_int64 (&schedule_iter, 2);
      period_months = (time_t) iterator_int64 (&schedule_iter, 3);
      duration = (time_t) iterator_int64 (&schedule_iter, 4);
      byday = iterator_int (&schedule_iter, 5);
      zone = iterator_string (&schedule_iter, 6);

      ical_component = icalendar_from_old_schedule_data (
        first_time, period, period_months, duration, byday, zone);
      quoted_ical = sql_quote (icalcomponent_as_ical_string (ical_component));

      g_debug ("%s: trash schedule %llu - first: %s (%s), period: %ld,"
               " period_months: %ld, duration: %ld - byday: %d\n"
               "generated iCalendar:\n%s",
               __FUNCTION__,
               schedule,
               iso_time_tz (&first_time, zone, NULL),
               zone,
               period,
               period_months,
               duration,
               byday,
               quoted_ical);

      sql ("UPDATE schedules_trash SET icalendar = '%s' WHERE id = %llu",
           quoted_ical,
           schedule);

      icalcomponent_free (ical_component);
      g_free (quoted_ical);
    }

  cleanup_iterator (&schedule_iter);

  /* Set the database version to 191. */

  set_db_version (191);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 191 to version 192.
 *
 * @return 0 success, -1 error.
 */
int
migrate_191_to_192 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 191. */

  if (manage_db_version () != 191)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The "classic" severity class was removed. */

  sql ("UPDATE settings SET value = 'nist'"
       " WHERE name = 'Severity Class' AND value = 'classic';");

  /* Set the database version to 192. */

  set_db_version (192);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 192 to version 193.
 *
 * @return 0 success, -1 error.
 */
int
migrate_192_to_193 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 192. */

  if (manage_db_version () != 192)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Create new tables for tag resources */

  sql ("CREATE TABLE IF NOT EXISTS tag_resources"
       " (tag integer REFERENCES tags (id),"
       "  resource_type text,"
       "  resource integer,"
       "  resource_uuid text,"
       "  resource_location integer);");

  sql ("CREATE TABLE IF NOT EXISTS tag_resources_trash"
       " (tag integer REFERENCES tags_trash (id),"
       "  resource_type text,"
       "  resource integer,"
       "  resource_uuid text,"
       "  resource_location integer);");

  /* Move tag resources to new tables */

  sql ("INSERT INTO tag_resources"
       " (tag, resource_type, resource, resource_uuid, resource_location)"
       " SELECT id, resource_type, resource, resource_uuid, resource_location"
       "   FROM tags"
       "  WHERE resource != 0");

  sql ("INSERT INTO tag_resources_trash"
       " (tag, resource_type, resource, resource_uuid, resource_location)"
       " SELECT id, resource_type, resource, resource_uuid, resource_location"
       "   FROM tags_trash"
       "  WHERE resource != 0");

  /* Drop tag resource columns except resource_type */

  sql ("ALTER TABLE tags DROP COLUMN resource;");
  sql ("ALTER TABLE tags DROP COLUMN resource_uuid;");
  sql ("ALTER TABLE tags DROP COLUMN resource_location;");

  sql ("ALTER TABLE tags_trash DROP COLUMN resource;");
  sql ("ALTER TABLE tags_trash DROP COLUMN resource_uuid;");
  sql ("ALTER TABLE tags_trash DROP COLUMN resource_location;");

  /* Set the database version to 193. */

  set_db_version (193);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 193 to version 194.
 *
 * @return 0 success, -1 error.
 */
int
migrate_193_to_194 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 193. */

  if (manage_db_version () != 193)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The version column was dropped from the nvts table. */

  sql ("ALTER TABLE nvts DROP COLUMN version;");

  /* Set the database version to 194. */

  set_db_version (194);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 194 to version 195.
 *
 * @return 0 success, -1 error.
 */
int
migrate_194_to_195 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 194. */

  if (manage_db_version () != 194)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The hostname column was added for the results table. */

  sql ("ALTER TABLE results ADD COLUMN hostname TEXT;");

  /* Set the database version to 195. */

  set_db_version (195);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 195 to version 196.
 *
 * @return 0 success, -1 error.
 */
int
migrate_195_to_196 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 195. */

  if (manage_db_version () != 195)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Ensure new tables exist. */

  sql ("CREATE TABLE IF NOT EXISTS results_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  task integer REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  host text,"
       "  port text,"
       "  nvt text,"
       "  result_nvt integer," // REFERENCES result_nvts (id),"
       "  type text,"
       "  description text,"
       "  report integer REFERENCES reports (id) ON DELETE RESTRICT,"
       "  nvt_version text,"
       "  severity real,"
       "  qod integer,"
       "  qod_type text,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  date integer,"
       "  hostname text);");

  /* Results of trashcan tasks are now stored in results_trash. */

  sql ("INSERT INTO results_trash"
       " (uuid, task, host, port, nvt, result_nvt, type, description,"
       "  report, nvt_version, severity, qod, qod_type, owner, date,"
       "  hostname)"
       " SELECT uuid, task, host, port, nvt, result_nvt, type,"
       "        description, report, nvt_version, severity, qod,"
       "         qod_type, owner, date, hostname"
       " FROM results"
       " WHERE task IN (SELECT id FROM tasks WHERE hidden = 2);");

  sql ("DELETE FROM results"
       " WHERE task IN (SELECT id FROM tasks WHERE hidden = 2);");

  /* Set the database version to 196. */

  set_db_version (196);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 196 to version 197.
 *
 * @return 0 success, -1 error.
 */
int
migrate_196_to_197 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 196. */

  if (manage_db_version () != 196)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The hidden column was removed from reports. */

  sql ("ALTER TABLE reports DROP COLUMN hidden;");

  /* Set the database version to 197. */

  set_db_version (197);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 197 to version 198.
 *
 * @return 0 success, -1 error.
 */
int
migrate_197_to_198 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 197. */

  if (manage_db_version () != 197)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The copyright column was removed from nvts. */

  sql ("ALTER TABLE nvts DROP COLUMN copyright;");

  /* Set the database version to 198. */

  set_db_version (198);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 198 to version 199.
 *
 * @return 0 success, -1 error.
 */
int
migrate_198_to_199 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 198. */

  if (manage_db_version () != 198)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Container target are now only 0, and never NULL. */

  sql ("UPDATE tasks SET target = 0 WHERE target IS NULL;");

  /* Set the database version to 199. */

  set_db_version (199);

  sql_commit ();

  return 0;
}

/**
 * @brief UUID of 'Discovery' NVT selector, for migrator.
 */
#define MIGRATE_TO_200_NVT_SELECTOR_UUID_DISCOVERY \
  "0d9a2738-8fe2-4e22-8f26-bb886179e759"

/**
 * @brief NVT selector type for "NVT" rule.
 */
#define MIGRATE_TO_200_NVT_SELECTOR_TYPE_NVT 2

/**
 * @brief Migrate the database from version 199 to version 200.
 *
 * @return 0 success, -1 error.
 */
int
migrate_199_to_200 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 199. */

  if (manage_db_version () != 199)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Various NVTs were added to and removed from the Discovery scan config. */

  // clang-format off
  sql ("DELETE FROM nvt_selectors WHERE "
       " name='" MIGRATE_TO_200_NVT_SELECTOR_UUID_DISCOVERY "'"
       " AND (family_or_nvt='1.3.6.1.4.1.25623.1.0.902799'"
       "      OR family_or_nvt='1.3.6.1.4.1.25623.1.0.13859'"
       "      OR family_or_nvt='1.3.6.1.4.1.25623.1.0.900188'"
       "      OR family_or_nvt='1.3.6.1.4.1.25623.1.0.100353'"
       "      OR family_or_nvt='1.3.6.1.4.1.25623.1.0.12639'"
       "      OR family_or_nvt='1.3.6.1.4.1.25623.1.0.900600'"
       "      OR family_or_nvt='1.3.6.1.4.1.25623.1.0.100075'"
       "      OR family_or_nvt='1.3.6.1.4.1.25623.1.0.100080'"
       "      OR family_or_nvt='1.3.6.1.4.1.25623.1.0.901206'"
       "      OR family_or_nvt='1.3.6.1.4.1.25623.1.0.10942');");

  sql ("INSERT into nvt_selectors"
       " (name, exclude, type, family_or_nvt, family)"
       " VALUES ('" MIGRATE_TO_200_NVT_SELECTOR_UUID_DISCOVERY "', 0,"
       "         " G_STRINGIFY (MIGRATE_TO_200_NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.108477', 'FTP'),"
       "        ('" MIGRATE_TO_200_NVT_SELECTOR_UUID_DISCOVERY "', 0,"
       "         " G_STRINGIFY (MIGRATE_TO_200_NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.108479', 'Service detection'),"
       "        ('" MIGRATE_TO_200_NVT_SELECTOR_UUID_DISCOVERY "', 0,"
       "         " G_STRINGIFY (MIGRATE_TO_200_NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.108102', 'Service detection'),"
       "        ('" MIGRATE_TO_200_NVT_SELECTOR_UUID_DISCOVERY "', 0,"
       "         " G_STRINGIFY (MIGRATE_TO_200_NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.108478', 'Service detection'),"
       "        ('" MIGRATE_TO_200_NVT_SELECTOR_UUID_DISCOVERY "', 0,"
       "         " G_STRINGIFY (MIGRATE_TO_200_NVT_SELECTOR_TYPE_NVT) ","
       "         '1.3.6.1.4.1.25623.1.0.10942', 'Service detection');");
  // clang-format on

  /* Set the database version to 200. */

  set_db_version (200);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 200 to version 201.
 *
 * @return 0 success, -1 error.
 */
int
migrate_200_to_201 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 200. */

  if (manage_db_version () != 200)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Ticket commands were added. */

  insert_permission ("get_tickets", ROLE_UUID_OBSERVER);

  insert_permission ("get_tickets", ROLE_UUID_USER);
  insert_permission ("create_ticket", ROLE_UUID_USER);
  insert_permission ("modify_ticket", ROLE_UUID_USER);
  insert_permission ("delete_ticket", ROLE_UUID_USER);

  /* Set the database version to 201. */

  set_db_version (201);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 201 to version 202.
 *
 * @return 0 success, -1 error.
 */
int
migrate_201_to_202 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 201. */

  if (manage_db_version () != 201)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Ensure the various tickets tables exist */
  sql ("CREATE TABLE IF NOT EXISTS tickets"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL," /* NVT name.  Aka Vulnerability. */
       "  comment text,"
       "  nvt text,"
       "  task integer," // REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  report integer," // REFERENCES reports (id) ON DELETE RESTRICT,"
       "  severity real,"
       "  host text,"
       "  location text,"
       "  solution_type text,"
       "  assigned_to integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  status integer,"
       "  open_time integer,"
       "  solved_time integer,"
       "  solved_comment text,"
       "  confirmed_time integer,"
       "  confirmed_report integer," // REFERENCES reports (id) ON DELETE RESTRICT,"
       "  closed_time integer,"
       "  closed_comment text,"
       "  orphaned_time integer,"
       "  creation_time integer,"
       "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS ticket_results"
       " (id SERIAL PRIMARY KEY,"
       "  ticket integer REFERENCES tickets (id) ON DELETE RESTRICT,"
       "  result integer,"    // REFERENCES results (id) ON DELETE RESTRICT
       "  result_location integer,"
       "  result_uuid text,"
       "  report integer);"); // REFERENCES reports (id) ON DELETE RESTRICT

  sql ("CREATE TABLE IF NOT EXISTS tickets_trash"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text NOT NULL," /* NVT name.  Aka Vulnerability. */
       "  comment text,"
       "  nvt text,"
       "  task integer," // REFERENCES tasks (id) ON DELETE RESTRICT,"
       "  report integer," // REFERENCES reports (id) ON DELETE RESTRICT,"
       "  severity real,"
       "  host text,"
       "  location text,"
       "  solution_type text,"
       "  assigned_to integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  status integer,"
       "  open_time integer,"
       "  solved_time integer,"
       "  solved_comment text,"
       "  confirmed_time integer,"
       "  confirmed_report integer," // REFERENCES reports (id) ON DELETE RESTRICT,"
       "  closed_time integer,"
       "  closed_comment text,"
       "  orphaned_time integer,"
       "  creation_time integer,"
      "  modification_time integer);");

  sql ("CREATE TABLE IF NOT EXISTS ticket_results_trash"
      " (id SERIAL PRIMARY KEY,"
      "  ticket integer REFERENCES tickets_trash (id) ON DELETE RESTRICT,"
      "  result integer,"    // REFERENCES results_trash (id) ON DELETE RESTRICT
      "  result_location integer,"
      "  result_uuid text,"
      "  report integer);"); // REFERENCES reports_trash (id) ON DELETE RESTRICT

  /* Ticket orphan state was removed. */

  sql ("UPDATE tickets SET status = 3 WHERE status = 4;");
  sql ("UPDATE tickets_trash SET status = 3 WHERE status = 4;");

  /* Set the database version to 202. */

  set_db_version (202);

  sql_commit ();

  return 0;
}

/**
 * @brief Rename a column.
 *
 * @param[in]  table  Table
 * @param[in]  old    Old column.
 * @param[in]  new    New column.
 */
static void
move (const gchar *table, const gchar *old, const gchar *new)
{
  sql ("ALTER TABLE %s RENAME COLUMN %s TO %s;", table, old, new);
}

/**
 * @brief Migrate the database from version 202 to version 203.
 *
 * @return 0 success, -1 error.
 */
int
migrate_202_to_203 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 202. */

  if (manage_db_version () != 202)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Ticket columns were renamed to match the state names. */

  sql ("ALTER TABLE tickets DROP COLUMN orphaned_time;");

  move ("tickets", "solved_comment", "fixed_comment");
  move ("tickets", "solved_time", "fixed_time");
  move ("tickets", "confirmed_report", "fix_verified_report");
  move ("tickets", "confirmed_time", "fix_verified_time");

  move ("tickets_trash", "solved_comment", "fixed_comment");
  move ("tickets_trash", "solved_time", "fixed_time");
  move ("tickets_trash", "confirmed_report", "fix_verified_report");
  move ("tickets_trash", "confirmed_time", "fix_verified_time");

  /* Set the database version to 203. */

  set_db_version (203);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 203 to version 204.
 *
 * @return 0 success, -1 error.
 */
int
migrate_203_to_204 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 203. */

  if (manage_db_version () != 203)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Ticket open_comment was added. */

  sql ("ALTER TABLE tickets ADD COLUMN open_comment text;");
  sql ("UPDATE tickets SET open_comment = 'No comment for migration.';");

  sql ("ALTER TABLE tickets_trash ADD COLUMN open_comment text;");
  sql ("UPDATE tickets_trash SET open_comment = 'No comment for migration.';");

  /* Set the database version to 204. */

  set_db_version (204);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 204 to version 205.
 *
 * @return 0 success, -1 error.
 */
int
migrate_204_to_205 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 204. */

  if (manage_db_version () != 204)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Ticket "comment" column suffix was changed to "note". */

  move ("tickets", "open_comment", "open_note");
  move ("tickets", "fixed_comment", "fixed_note");
  move ("tickets", "closed_comment", "closed_note");

  move ("tickets_trash", "open_comment", "open_note");
  move ("tickets_trash", "fixed_comment", "fixed_note");
  move ("tickets_trash", "closed_comment", "closed_note");

  /* Set the database version to 205. */

  set_db_version (205);

  sql_commit ();

  return 0;
}

/**
 * @brief Converts old NVT preferences to the new format.
 *
 * @param[in]  table_name  The name of the table to update.
 */
static void
replace_preference_names_205_to_206 (const char *table_name)
{
  iterator_t preferences;

  init_iterator (&preferences,
                 "SELECT id, name"
                 " FROM \"%s\""
                 " WHERE name LIKE '%%[%%]:%%';",
                 table_name);

  while (next (&preferences))
    {
      resource_t rowid;
      const char *old_name;
      char *start, *end;
      gchar *nvt_name, *type, *preference;
      char *oid, *new_name, *quoted_nvt_name, *quoted_new_name;

      rowid = iterator_int64 (&preferences, 0);
      old_name = iterator_string (&preferences, 1);

      // Text before first "["
      end = strstr (old_name, "[");
      nvt_name = g_strndup (old_name, end - old_name);
      // Text between first "[" and first "]"
      start = end + 1;
      end = strstr (start, "]");
      type = g_strndup (start, end - start);
      // Text after first ":" after first "]"
      start = strstr (end, ":") + 1;
      preference = g_strdup (start);

      // Find OID:
      quoted_nvt_name = sql_quote (nvt_name);
      oid =
        sql_string ("SELECT oid FROM nvts WHERE name = '%s';", quoted_nvt_name);

      // Update
      if (oid)
        {
          new_name = g_strdup_printf ("%s:%s:%s", oid, type, preference);
          quoted_new_name = sql_quote (new_name);
          sql ("UPDATE \"%s\" SET name = '%s' WHERE id = %llu",
               table_name,
               quoted_new_name,
               rowid);
        }
      else
        {
          new_name = NULL;
          quoted_new_name = NULL;
          g_warning ("No NVT named '%s' found", nvt_name);
        }

      g_free (nvt_name);
      g_free (quoted_nvt_name);
      g_free (type);
      g_free (preference);
      free (oid);
      g_free (new_name);
      g_free (quoted_new_name);
    }
  cleanup_iterator (&preferences);
}

/**
 * @brief Migrate the database from version 205 to version 206.
 *
 * @return 0 success, -1 error.
 */
int
migrate_205_to_206 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 205. */

  if (manage_db_version () != 205)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Change NVT preferences to new style */
  replace_preference_names_205_to_206 ("nvt_preferences");

  /* Change config preferences to new style */
  replace_preference_names_205_to_206 ("config_preferences");

  /* Change trash config preferences to new style */
  replace_preference_names_205_to_206 ("config_preferences_trash");

  /* Set the database version to 206. */

  set_db_version (206);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 206 to version 207.
 *
 * @return 0 success, -1 error.
 */
int
migrate_206_to_207 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 206. */

  if (manage_db_version () != 206)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* User are now able to see themselves by default. */

  sql ("INSERT INTO permissions"
       " (uuid, owner, name, comment, resource_type, resource_uuid, resource,"
       "  resource_location, subject_type, subject, subject_location,"
       "  creation_time, modification_time)"
       " SELECT make_uuid (), id, 'get_users',"
       "        'Automatically created when adding user', 'user', uuid, id, 0,"
       "        'user', id, 0, m_now (), m_now ()"
       " FROM users"
       " WHERE NOT"
       "       EXISTS (SELECT * FROM permissions"
       "               WHERE name = 'get_users'"
       "               AND resource = users.id"
       "               AND subject = users.id"
       "               AND comment"
       "                   = 'Automatically created when adding user');");

  /* Set the database version to 207. */

  set_db_version (207);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 207 to version 208.
 *
 * @return 0 success, -1 error.
 */
int
migrate_207_to_208 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 207. */

  if (manage_db_version () != 207)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Remove NOBID, NOCVE and NOXREF entries. An empty string will
   * from now on indicate that there is no reference of the
   * respective type. */

  sql ("UPDATE nvts SET bid = '' WHERE bid LIKE 'NOBID';");
  sql ("UPDATE nvts SET cve = '' WHERE cve LIKE 'NOCVE';");
  sql ("UPDATE nvts SET xref = '' WHERE xref LIKE 'NOXREF';");

  /* Set the database version to 208. */

  set_db_version (208);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 208 to version 209.
 *
 * @return 0 success, -1 error.
 */
int
migrate_208_to_209 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 208. */

  if (manage_db_version () != 208)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Drop the now-unused table "nvt_cves". */

  sql ("DROP TABLE IF EXISTS nvt_cves;");

  /* Set the database version to 209. */

  set_db_version (209);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 209 to version 210.
 *
 * @return 0 success, -1 error.
 */
int
migrate_209_to_210 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 209. */

  if (manage_db_version () != 209)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Remove the fields "bid" and "xref" from table "nvts". */

  sql ("ALTER TABLE IF EXISTS nvts DROP COLUMN bid CASCADE;");
  sql ("ALTER TABLE IF EXISTS nvts DROP COLUMN xref CASCADE;");

  /* Set the database version to 210. */

  set_db_version (210);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 210 to version 211.
 *
 * @return 0 success, -1 error.
 */
int
migrate_210_to_211 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 210. */

  if (manage_db_version () != 210)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Remove any entry in table "results" where field "nvt" is '0'.
   * The oid '0' was used to inidcate a open port detection in very early
   * versions. This migration ensures there are no more such
   * results although it is very unlikely the case. */

  sql ("DELETE FROM results WHERE nvt = '0';");

  /* Set the database version to 211. */

  set_db_version (211);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 211 to version 212.
 *
 * @return 0 success, -1 error.
 */
int
migrate_211_to_212 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 211. */

  if (manage_db_version () != 211)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Add usage_type columns to configs and tasks */
  sql ("ALTER TABLE configs ADD COLUMN usage_type text;");
  sql ("ALTER TABLE configs_trash ADD COLUMN usage_type text;");
  sql ("ALTER TABLE tasks ADD COLUMN usage_type text;");

  sql ("UPDATE configs SET usage_type = 'scan'");
  sql ("UPDATE configs_trash SET usage_type = 'scan'");
  sql ("UPDATE tasks SET usage_type = 'scan'");

  /* Set the database version to 212. */

  set_db_version (212);

  sql_commit ();

  return 0;
}

#undef UPDATE_DASHBOARD_SETTINGS

/**
 * @brief The oldest version for which migration is supported
 */
#define MIGRATE_MIN_OLD_VERSION 184

/**
 * @brief Array of database version migrators.
 */
static migrator_t database_migrators[] = {
  {185, migrate_184_to_185}, // v7.0: rev 184
  {186, migrate_185_to_186},
  {187, migrate_186_to_187},
  {188, migrate_187_to_188},
  {189, migrate_188_to_189},
  {190, migrate_189_to_190},
  {191, migrate_190_to_191},
  {192, migrate_191_to_192},
  {193, migrate_192_to_193},
  {194, migrate_193_to_194},
  {195, migrate_194_to_195},
  {196, migrate_195_to_196},
  {197, migrate_196_to_197},
  {198, migrate_197_to_198},
  {199, migrate_198_to_199},
  {200, migrate_199_to_200},
  {201, migrate_200_to_201},
  {202, migrate_201_to_202},
  {203, migrate_202_to_203},
  {204, migrate_203_to_204},
  {205, migrate_204_to_205}, // v8.0: rev 205
  {206, migrate_205_to_206},
  {207, migrate_206_to_207},
  {208, migrate_207_to_208},
  {209, migrate_208_to_209},
  {210, migrate_209_to_210},
  {211, migrate_210_to_211},
  {212, migrate_211_to_212},
  /* End marker. */
  {-1, NULL}};

/**
 * @brief Check whether the migration needs the real timezone.
 *
 * @param[in]  log_config  Log configuration.
 * @param[in]  database    Location of manage database.
 *
 * @return TRUE if yes, else FALSE.
 */
gboolean
manage_migrate_needs_timezone (GSList *log_config, const gchar *database)
{
  int db_version;
  g_log_set_handler (
    G_LOG_DOMAIN, ALL_LOG_LEVELS, (GLogFunc) gvm_log_func, log_config);
  init_manage_process (0, database);
  db_version = manage_db_version ();
  cleanup_manage_process (TRUE);
  return db_version > 0 && db_version < 52;
}

/**
 * @brief Check whether a migration is available.
 *
 * @param[in]  old_version  Version to migrate from.
 * @param[in]  new_version  Version to migrate to.
 *
 * @return 1 yes, 0 no, -1 error.
 */
static int
migrate_is_available (int old_version, int new_version)
{
  migrator_t *migrators;

  if (old_version < MIGRATE_MIN_OLD_VERSION)
    return 0;

  migrators = database_migrators + old_version - MIGRATE_MIN_OLD_VERSION;

  while ((migrators->version >= 0) && (migrators->version <= new_version))
    {
      if (migrators->function == NULL)
        return 0;
      if (migrators->version == new_version)
        return 1;
      migrators++;
    }

  return -1;
}

/**
 * @brief Migrate database to version supported by this manager.
 *
 * @param[in]  log_config  Log configuration.
 * @param[in]  database    Location of manage database.
 *
 * @return 0 success, 1 already on supported version, 2 too hard,
 * 11 cannot migrate SCAP DB, 12 cannot migrate CERT DB,
 * -1 error, -11 error running SCAP migration, -12 error running CERT migration.
 */
int
manage_migrate (GSList *log_config, const gchar *database)
{
  migrator_t *migrators;
  /* The version on the disk. */
  int old_version, old_scap_version, old_cert_version;
  /* The version that this program requires. */
  int new_version, new_scap_version, new_cert_version;
  int version_current = 0, scap_version_current = 0, cert_version_current = 0;

  g_log_set_handler (
    G_LOG_DOMAIN, ALL_LOG_LEVELS, (GLogFunc) gvm_log_func, log_config);

  init_manage_process (0, database);

  old_version = manage_db_version ();
  new_version = manage_db_supported_version ();

  if (old_version == -1)
    {
      cleanup_manage_process (TRUE);
      return -1;
    }

  if (old_version == -2)
    {
      g_warning ("%s: no task tables yet, so no need to migrate them",
                 __FUNCTION__);
      version_current = 1;
    }
  else if (old_version == new_version)
    {
      version_current = 1;
    }
  else
    {
      switch (migrate_is_available (old_version, new_version))
        {
        case -1:
          cleanup_manage_process (TRUE);
          return -1;
        case 0:
          cleanup_manage_process (TRUE);
          return 2;
        }

      /* Call the migrators to take the DB from the old version to the new. */

      migrators = database_migrators + old_version - MIGRATE_MIN_OLD_VERSION;

      while ((migrators->version >= 0) && (migrators->version <= new_version))
        {
          if (migrators->function == NULL)
            {
              cleanup_manage_process (TRUE);
              return -1;
            }

          g_info ("   Migrating to %i", migrators->version);

          if (migrators->function ())
            {
              cleanup_manage_process (TRUE);
              return -1;
            }
          migrators++;
        }
    }

  /* Migrate SCAP and CERT databases */
  old_scap_version = manage_scap_db_version ();
  new_scap_version = manage_scap_db_supported_version ();
  old_cert_version = manage_cert_db_version ();
  new_cert_version = manage_cert_db_supported_version ();

  if (old_scap_version == new_scap_version)
    {
      g_debug ("SCAP database already at current version");
      scap_version_current = 1;
    }
  else if (old_scap_version == -1)
    {
      g_message ("No SCAP database found for migration");
      scap_version_current = 1;
    }
  else if (old_scap_version > new_scap_version)
    {
      g_warning ("SCAP database version too new: %d", old_scap_version);
      return 11;
    }
  else
    {
      g_message ("Migrating SCAP database");
      switch (gvm_migrate_secinfo (SCAP_FEED))
        {
        case 0:
          g_message ("SCAP database migrated successfully");
          break;
        case 1:
          g_warning ("SCAP sync already running");
          cleanup_manage_process (TRUE);
          return 11;
          break;
        default:
          assert (0);
        case -1:
          cleanup_manage_process (TRUE);
          return -11;
          break;
        }
    }

  if (old_cert_version == new_cert_version)
    {
      g_debug ("CERT database already at current version");
      cert_version_current = 1;
    }
  else if (old_cert_version == -1)
    {
      g_message ("No CERT database found for migration");
      cert_version_current = 1;
    }
  else if (old_cert_version > new_cert_version)
    {
      g_warning ("CERT database version too new: %d", old_cert_version);
      return 12;
    }
  else
    {
      g_message ("Migrating CERT database");
      switch (gvm_migrate_secinfo (CERT_FEED))
        {
        case 0:
          g_message ("CERT database migrated successfully");
          break;
        case 1:
          g_warning ("CERT sync already running");
          cleanup_manage_process (TRUE);
          return 12;
          break;
        default:
          assert (0);
        case -1:
          cleanup_manage_process (TRUE);
          return -12;
          break;
        }
    }

  if (version_current && scap_version_current && cert_version_current)
    {
      cleanup_manage_process (TRUE);
      return 1;
    }

  /* We now run ANALYZE after migrating, instead of on every startup.  ANALYZE
   * made startup too slow, especially for large databases.  Running it here
   * is preferred over removing it entirely, because users may have very
   * different use patterns of the database.
   *
   * Reopen the database before the ANALYZE, in case the schema has changed. */
  cleanup_manage_process (TRUE);
  init_manage_process (0, database);
  sql ("ANALYZE;");

  cleanup_manage_process (TRUE);
  return 0;
}
