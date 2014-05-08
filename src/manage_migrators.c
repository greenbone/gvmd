/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the DB migrators.
 *
 * Authors:
 * Hani Benhabiles <hani.benhabiles@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2013 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
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
 * @brief The OpenVAS Manager DB Migrators file.
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
 *    the increase of OPENVASMD_DATABASE_VERSION, with an entry like
 *
 *        * CMakeLists.txt (OPENVASMD_DATABASE_VERSION): Increase to 6, for...
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

#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <glib/gstdio.h>
#include <assert.h>
#include <sys/stat.h>
#include <ctype.h>
#include <dirent.h>

#include "manage_sql.h"
#include "sql.h"
#include "tracef.h"

#include <openvas/misc/openvas_uuid.h>
#include <openvas/base/openvas_file.h>
#include <openvas/misc/openvas_logging.h>

/* Types */

/**
 * @brief A migrator.
 */
typedef struct
{
  int version;         ///< Version that the migrator produces.
  int (*function) ();  ///< Function that does the migration.  NULL if too hard.
} migrator_t;

/* Functions */

/**
 * @brief Create all tables, using the version 4 schema.
 */
static void
create_tables_version_4 ()
{
  sql ("CREATE TABLE IF NOT EXISTS config_preferences"
       " (id INTEGER PRIMARY KEY, config INTEGER, type, name, value);");
  sql ("CREATE TABLE IF NOT EXISTS configs"
       " (id INTEGER PRIMARY KEY, name UNIQUE, nvt_selector, comment,"
       "  family_count INTEGER, nvt_count INTEGER, families_growing INTEGER,"
       "  nvts_growing INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS lsc_credentials"
       " (id INTEGER PRIMARY KEY, name, password, comment, public_key TEXT,"
       "  private_key TEXT, rpm TEXT, deb TEXT, exe TEXT);");
  sql ("CREATE TABLE IF NOT EXISTS meta"
       " (id INTEGER PRIMARY KEY, name UNIQUE, value);");
  sql ("CREATE TABLE IF NOT EXISTS nvt_preferences"
       " (id INTEGER PRIMARY KEY, name, value);");
  /* nvt_selectors types: 0 all, 1 family, 2 NVT (NVT_SELECTOR_TYPE_* above). */
  sql ("CREATE TABLE IF NOT EXISTS nvt_selectors"
       " (id INTEGER PRIMARY KEY, name, exclude INTEGER, type INTEGER,"
       "  family_or_nvt, family);");
  sql ("CREATE TABLE IF NOT EXISTS nvts"
       " (id INTEGER PRIMARY KEY, oid, version, name, summary, description,"
       "  copyright, cve, bid, xref, tag, sign_key_ids, category INTEGER,"
       "  family);");
  sql ("CREATE TABLE IF NOT EXISTS report_hosts"
       " (id INTEGER PRIMARY KEY, report INTEGER, host, start_time, end_time,"
       "  attack_state, current_port, max_port);");
  sql ("CREATE INDEX IF NOT EXISTS report_hosts_by_report_and_host"
       " ON report_hosts (report, host);");
  sql ("CREATE TABLE IF NOT EXISTS report_results"
       " (id INTEGER PRIMARY KEY, report INTEGER, result INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS reports"
       " (id INTEGER PRIMARY KEY, uuid, hidden INTEGER, task INTEGER,"
       "  date INTEGER, start_time, end_time, nbefile, comment,"
       "  scan_run_status INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS results"
       " (id INTEGER PRIMARY KEY, task INTEGER, subnet, host, port, nvt, type,"
       "  description)");
  sql ("CREATE TABLE IF NOT EXISTS targets"
       " (id INTEGER PRIMARY KEY, name, hosts, comment);");
  sql ("CREATE TABLE IF NOT EXISTS task_files"
       " (id INTEGER PRIMARY KEY, task INTEGER, name, content);");
  sql ("CREATE TABLE IF NOT EXISTS tasks"
       " (id INTEGER PRIMARY KEY, uuid, name, hidden INTEGER, time, comment,"
       "  description, owner" /** @todo INTEGER */ ", run_status INTEGER,"
       "  start_time, end_time, config, target);");
  sql ("CREATE TABLE IF NOT EXISTS users"
       " (id INTEGER PRIMARY KEY, name UNIQUE, password);");
}

/**
 * @brief Migrate the database from version 0 to version 1.
 *
 * @return 0 success, -1 error.
 */
int
migrate_0_to_1 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 0. */

  if (manage_db_version () != 0)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* In SVN the database version flag changed from 0 to 1 on 2009-09-30,
   * while the database changed to the version 1 schema on 2009-08-29.  This
   * means the database could be flagged as version 0 while it has a version
   * 1 schema.  In this case the ADD COLUMN below would fail.  A work around
   * would be simply to update the version number to 1 in the database by
   * hand. */

  sql ("ALTER TABLE reports ADD COLUMN scan_run_status INTEGER;");

  /* SQLite 3.1.3 and earlier requires a VACUUM before it can read
   * from the new column.  However, vacuuming might change the ROWIDs,
   * which would screw up the data.  Debian 5.0 (Lenny) is 3.5.9-6
   * already. */

  sql ("UPDATE reports SET scan_run_status = '%u';",
       TASK_STATUS_INTERNAL_ERROR);

  sql ("UPDATE reports SET scan_run_status = '%u'"
       " WHERE start_time IS NULL OR end_time IS NULL;",
       TASK_STATUS_STOPPED);

  sql ("UPDATE reports SET scan_run_status = '%u'"
       " WHERE end_time IS NOT NULL;",
       TASK_STATUS_DONE);

  /* Set the database version to 1. */

  set_db_version (1);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 1 to version 2.
 *
 * @return 0 success, -1 error.
 */
int
migrate_1_to_2 ()
{
  iterator_t nvts;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 1. */

  if (manage_db_version () != 1)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The category column in nvts changed type from string to int.  This
   * may be a redundant conversion, as SQLite may have converted these
   * values automatically in each query anyway. */

  init_iterator (&nvts, "SELECT ROWID, category FROM nvts;");
  while (next (&nvts))
    {
      int category;
      const char *category_string;

      category_string = (const char*) sqlite3_column_text (nvts.stmt, 1);

      category = atoi (category_string);
      sql ("UPDATE nvts SET category = %i WHERE ROWID = %llu;",
           category,
           iterator_int64 (&nvts, 0));
    }
  cleanup_iterator (&nvts);

  /* Set the database version to 2. */

  set_db_version (2);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 2 to version 3.
 *
 * @return 0 success, -1 error.
 */
int
migrate_2_to_3 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 2. */

  if (manage_db_version () != 2)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Add tables added since version 2 that are adjust later in the
   * migration. */

  sql ("CREATE TABLE IF NOT EXISTS lsc_credentials (name, comment, rpm, deb, dog);");

  /* The lsc_credentials table changed: package columns changed type from BLOB
   * to string, new columns "password", "public key" and "private key" appeared
   * and the dog column changed name to exe.
   *
   * Just remove all the LSC credentials, as credential generation only
   * started working after version 3. */

  sql ("DELETE from lsc_credentials;");
  /* Before revision 5769 this could have caused problems, because these
   * columns are added on the end of the table, so columns referenced by
   * position in * queries may have been wrong (for example, with the iterator
   * returned by init_lsc_credential_iterator).  Since 5769 the queries
   * name all columns explicitly. */
  sql ("ALTER TABLE lsc_credentials ADD COLUMN password;");
  sql ("ALTER TABLE lsc_credentials ADD COLUMN public_key TEXT;");
  sql ("ALTER TABLE lsc_credentials ADD COLUMN private_key TEXT;");
  sql ("ALTER TABLE lsc_credentials ADD COLUMN exe TEXT;");

  /* Set the database version to 3. */

  set_db_version (3);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 3 to version 4.
 *
 * @return 0 success, -1 error.
 */
int
migrate_3_to_4 ()
{
  iterator_t nvts;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 3. */

  if (manage_db_version () != 3)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The nvt_selectors table got a family column. */

  sql ("ALTER TABLE nvt_selectors ADD COLUMN family;");

  init_nvt_selector_iterator (&nvts, NULL, (config_t) 0, 2);
  while (next (&nvts))
    {
      gchar *quoted_name = sql_quote (nvt_selector_iterator_name (&nvts));
      gchar *quoted_nvt = sql_quote (nvt_selector_iterator_nvt (&nvts));
      sql ("UPDATE nvt_selectors SET family ="
           " (SELECT family FROM nvts where oid = '%s')"
           " WHERE name = '%s';",
           quoted_nvt, quoted_name);
      g_free (quoted_name);
      g_free (quoted_nvt);
    }
  cleanup_iterator (&nvts);

  /* Set the database version to 4. */

  set_db_version (4);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Move all the data to the new tables for the 4 to 5 migrator.
 */
void
migrate_4_to_5_copy_data ()
{
  iterator_t rows;

  /* Table config_preferences. */
  init_iterator (&rows,
                 "SELECT rowid, config, type, name, value"
                 " FROM config_preferences_4;");
  while (next (&rows))
    {
      gchar *quoted_type = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_name = sql_insert (iterator_string (&rows, 3));
      gchar *quoted_value = sql_insert (iterator_string (&rows, 4));
      sql ("INSERT into config_preferences (id, config, type, name, value)"
           " VALUES (%llu, %llu, %s, %s, %s);",
           iterator_int64 (&rows, 0),
           iterator_int64 (&rows, 1),
           quoted_type,
           quoted_name,
           quoted_value);
      g_free (quoted_type);
      g_free (quoted_name);
      g_free (quoted_value);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE config_preferences_4;");

  /* Table configs. */
  init_iterator (&rows,
                 "SELECT rowid, name, nvt_selector, comment, family_count,"
                 " nvt_count, families_growing, nvts_growing"
                 " FROM configs_4;");
  while (next (&rows))
    {
      gchar *quoted_name = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_nvt_selector = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_comment = sql_insert (iterator_string (&rows, 3));
      sql ("INSERT into configs"
           " (id, name, nvt_selector, comment, family_count, nvt_count,"
           "  families_growing, nvts_growing)"
           " VALUES"
           " (%llu, %s, %s, %s, %llu, %llu, %llu, %llu);",
           iterator_int64 (&rows, 0),
           quoted_name,
           quoted_nvt_selector,
           quoted_comment,
           iterator_int64 (&rows, 4),
           iterator_int64 (&rows, 5),
           iterator_int64 (&rows, 6),
           iterator_int64 (&rows, 7));
      g_free (quoted_name);
      g_free (quoted_nvt_selector);
      g_free (quoted_comment);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE configs_4;");

  /* Table lsc_credentials. */
  init_iterator (&rows,
                 "SELECT rowid, name, password, comment, public_key,"
                 " private_key, rpm, deb, exe"
                 " FROM lsc_credentials_4;");
  while (next (&rows))
    {
      gchar *quoted_name = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_password = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_comment = sql_insert (iterator_string (&rows, 3));
      gchar *quoted_public_key = sql_insert (iterator_string (&rows, 4));
      gchar *quoted_private_key = sql_insert (iterator_string (&rows, 5));
      gchar *quoted_rpm = sql_insert (iterator_string (&rows, 6));
      gchar *quoted_deb = sql_insert (iterator_string (&rows, 7));
      gchar *quoted_exe = sql_insert (iterator_string (&rows, 8));
      sql ("INSERT into lsc_credentials"
           " (id, name, password, comment, public_key, private_key, rpm, deb,"
           "  exe)"
           " VALUES"
           " (%llu, %s, %s, %s, %s, %s, %s, %s, %s);",
           iterator_int64 (&rows, 0),
           quoted_name,
           quoted_password,
           quoted_comment,
           quoted_public_key,
           quoted_private_key,
           quoted_rpm,
           quoted_deb,
           quoted_exe);
      g_free (quoted_name);
      g_free (quoted_password);
      g_free (quoted_comment);
      g_free (quoted_public_key);
      g_free (quoted_private_key);
      g_free (quoted_rpm);
      g_free (quoted_deb);
      g_free (quoted_exe);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE lsc_credentials_4;");

  /* Table meta. */
  init_iterator (&rows, "SELECT rowid, name, value FROM meta_4;");
  while (next (&rows))
    {
      gchar *quoted_name = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_value = sql_insert (iterator_string (&rows, 2));
      sql ("INSERT into meta (id, name, value)"
           " VALUES (%llu, %s, %s);",
           iterator_int64 (&rows, 0),
           quoted_name,
           quoted_value);
      g_free (quoted_name);
      g_free (quoted_value);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE meta_4;");

  /* Table nvt_preferences. */
  init_iterator (&rows, "SELECT rowid, name, value FROM nvt_preferences_4;");
  while (next (&rows))
    {
      gchar *quoted_name = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_value = sql_insert (iterator_string (&rows, 2));
      sql ("INSERT into nvt_preferences (id, name, value)"
           " VALUES (%llu, %s, %s);",
           iterator_int64 (&rows, 0),
           quoted_name,
           quoted_value);
      g_free (quoted_name);
      g_free (quoted_value);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE nvt_preferences_4;");

  /* Table nvt_selectors. */
  init_iterator (&rows,
                 "SELECT rowid, name, exclude, type, family_or_nvt, family"
                 " FROM nvt_selectors_4;");
  while (next (&rows))
    {
      gchar *quoted_name = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_family_or_nvt = sql_insert (iterator_string (&rows, 4));
      gchar *quoted_family = sql_insert (iterator_string (&rows, 5));
      sql ("INSERT into nvt_selectors"
           " (id, name, exclude, type, family_or_nvt, family)"
           " VALUES"
           " (%llu, %s, %llu, %llu, %s, %s);",
           iterator_int64 (&rows, 0),
           quoted_name,
           iterator_int64 (&rows, 2),
           iterator_int64 (&rows, 3),
           quoted_family_or_nvt,
           quoted_family);
      g_free (quoted_name);
      g_free (quoted_family_or_nvt);
      g_free (quoted_family);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE nvt_selectors_4;");

  /* Table nvts. */
  init_iterator (&rows,
                 "SELECT rowid, oid, version, name, summary, description,"
                 " copyright, cve, bid, xref, tag, sign_key_ids, category,"
                 " family"
                 " FROM nvts_4;");
  while (next (&rows))
    {
      gchar *quoted_oid = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_version = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_name = sql_insert (iterator_string (&rows, 3));
      gchar *quoted_summary = sql_insert (iterator_string (&rows, 4));
      gchar *quoted_description = sql_insert (iterator_string (&rows, 5));
      gchar *quoted_copyright = sql_insert (iterator_string (&rows, 6));
      gchar *quoted_cve = sql_insert (iterator_string (&rows, 7));
      gchar *quoted_bid = sql_insert (iterator_string (&rows, 8));
      gchar *quoted_xref = sql_insert (iterator_string (&rows, 9));
      gchar *quoted_tag = sql_insert (iterator_string (&rows, 10));
      gchar *quoted_sign_key_ids = sql_insert (iterator_string (&rows, 11));
      gchar *quoted_family = sql_insert (iterator_string (&rows, 13));

      {
        /* Starting from revision 5726 on 2009-10-26 (just before 0.9.2),
         * the Manager converts semicolons in OTP NVT descriptions to newlines
         * before entering them in the database.  Convert the existing
         * semicolons here, because it is a convenient place to do it. */
        gchar* pos = quoted_description;
        while ((pos = strchr (pos, ';')))
          pos[0] = '\n';
      }

      sql ("INSERT into nvts"
           " (id, oid, version, name, summary, description, copyright, cve,"
           "  bid, xref, tag, sign_key_ids, category, family)"
           " VALUES"
           " (%llu, %s, %s, %s, %s, %s, %s, %s, %s, %s,"
           "  %s, %s, %llu, %s);",
           iterator_int64 (&rows, 0),
           quoted_oid,
           quoted_version,
           quoted_name,
           quoted_summary,
           quoted_description,
           quoted_copyright,
           quoted_cve,
           quoted_bid,
           quoted_xref,
           quoted_tag,
           quoted_sign_key_ids,
           iterator_int64 (&rows, 12),
           quoted_family);
      g_free (quoted_oid);
      g_free (quoted_version);
      g_free (quoted_name);
      g_free (quoted_summary);
      g_free (quoted_description);
      g_free (quoted_copyright);
      g_free (quoted_cve);
      g_free (quoted_bid);
      g_free (quoted_xref);
      g_free (quoted_tag);
      g_free (quoted_sign_key_ids);
      g_free (quoted_family);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE nvts_4;");

  /* Table report_hosts. */
  init_iterator (&rows,
                 "SELECT rowid, report, host, start_time, end_time,"
                 " attack_state, current_port, max_port"
                 " FROM report_hosts_4;");
  while (next (&rows))
    {
      gchar *quoted_host = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_start_time = sql_insert (iterator_string (&rows, 3));
      gchar *quoted_end_time = sql_insert (iterator_string (&rows, 4));
      gchar *quoted_attack_state = sql_insert (iterator_string (&rows, 5));
      gchar *quoted_current_port = sql_insert (iterator_string (&rows, 6));
      gchar *quoted_max_port = sql_insert (iterator_string (&rows, 7));
      sql ("INSERT into report_hosts"
           " (id, report, host, start_time, end_time, attack_state,"
           "  current_port, max_port)"
           " VALUES"
           " (%llu, %llu, %s, %s, %s, %s, %s, %s);",
           iterator_int64 (&rows, 0),
           iterator_int64 (&rows, 1),
           quoted_host,
           quoted_start_time,
           quoted_end_time,
           quoted_attack_state,
           quoted_current_port,
           quoted_max_port);
      g_free (quoted_host);
      g_free (quoted_start_time);
      g_free (quoted_end_time);
      g_free (quoted_attack_state);
      g_free (quoted_current_port);
      g_free (quoted_max_port);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE report_hosts_4;");

  /* Table report_results. */
  init_iterator (&rows, "SELECT rowid, report, result FROM report_results_4;");
  while (next (&rows))
    {
      sql ("INSERT into report_results (id, report, result)"
           " VALUES (%llu, %llu, %llu)",
           iterator_int64 (&rows, 0),
           iterator_int64 (&rows, 1),
           iterator_int64 (&rows, 2));
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE report_results_4;");

  /* Table reports. */
  init_iterator (&rows,
                 "SELECT rowid, uuid, hidden, task, date, start_time, end_time,"
                 " nbefile, comment, scan_run_status"
                 " FROM reports_4;");
  while (next (&rows))
    {
      gchar *quoted_uuid = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_start_time = sql_insert (iterator_string (&rows, 5));
      gchar *quoted_end_time = sql_insert (iterator_string (&rows, 6));
      gchar *quoted_nbefile = sql_insert (iterator_string (&rows, 7));
      gchar *quoted_comment = sql_insert (iterator_string (&rows, 8));
      sql ("INSERT into reports"
           " (id, uuid, hidden, task, date, start_time, end_time, nbefile,"
           "  comment, scan_run_status)"
           " VALUES"
           " (%llu, %s, %llu, %llu, %llu, %s, %s, %s, %s, %llu);",
           iterator_int64 (&rows, 0),
           quoted_uuid,
           iterator_int64 (&rows, 2),
           iterator_int64 (&rows, 3),
           iterator_int64 (&rows, 4),
           quoted_start_time,
           quoted_end_time,
           quoted_nbefile,
           quoted_comment,
           iterator_int64 (&rows, 9));
      g_free (quoted_uuid);
      g_free (quoted_start_time);
      g_free (quoted_end_time);
      g_free (quoted_nbefile);
      g_free (quoted_comment);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE reports_4;");

  /* Table results. */
  init_iterator (&rows,
                 "SELECT rowid, task, subnet, host, port, nvt, type,"
                 " description"
                 " FROM results_4;");
  while (next (&rows))
    {
      gchar *quoted_subnet = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_host = sql_insert (iterator_string (&rows, 3));
      gchar *quoted_port = sql_insert (iterator_string (&rows, 4));
      gchar *quoted_nvt = sql_insert (iterator_string (&rows, 5));
      gchar *quoted_type = sql_insert (iterator_string (&rows, 6));
      gchar *quoted_description = sql_insert (iterator_string (&rows, 7));
      sql ("INSERT into results"
           " (id, task, subnet, host, port, nvt, type, description)"
           " VALUES"
           " (%llu, %llu, %s, %s, %s, %s, %s, %s);",
           iterator_int64 (&rows, 0),
           iterator_int64 (&rows, 1),
           quoted_subnet,
           quoted_host,
           quoted_port,
           quoted_nvt,
           quoted_type,
           quoted_description);
      g_free (quoted_subnet);
      g_free (quoted_host);
      g_free (quoted_port);
      g_free (quoted_nvt);
      g_free (quoted_type);
      g_free (quoted_description);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE results_4;");

  /* Table targets. */
  init_iterator (&rows, "SELECT rowid, name, hosts, comment FROM targets_4;");
  while (next (&rows))
    {
      gchar *quoted_name = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_hosts = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_comment = sql_insert (iterator_string (&rows, 3));
      sql ("INSERT into targets (id, name, hosts, comment)"
           " VALUES (%llu, %s, %s, %s);",
           iterator_int64 (&rows, 0),
           quoted_name,
           quoted_hosts,
           quoted_comment);
      g_free (quoted_name);
      g_free (quoted_hosts);
      g_free (quoted_comment);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE targets_4;");

  /* Table task_files. */
  init_iterator (&rows, "SELECT rowid, task, name, content FROM task_files_4;");
  while (next (&rows))
    {
      gchar *quoted_name = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_content = sql_insert (iterator_string (&rows, 3));
      sql ("INSERT into task_files (id, task, name, content)"
           " VALUES (%llu, %llu, %s, %s);",
           iterator_int64 (&rows, 0),
           iterator_int64 (&rows, 1),
           quoted_name,
           quoted_content);
      g_free (quoted_name);
      g_free (quoted_content);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE task_files_4;");

  /* Table tasks. */
  init_iterator (&rows,
                 "SELECT rowid, uuid, name, hidden, time, comment, description,"
                 " owner, run_status, start_time, end_time, config, target"
                 " FROM tasks_4;");
  while (next (&rows))
    {
      gchar *quoted_uuid = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_name = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_time = sql_insert (iterator_string (&rows, 4));
      gchar *quoted_comment = sql_insert (iterator_string (&rows, 5));
      gchar *quoted_description = sql_insert (iterator_string (&rows, 6));
      gchar *quoted_start_time = sql_insert (iterator_string (&rows, 9));
      gchar *quoted_end_time = sql_insert (iterator_string (&rows, 10));
      gchar *quoted_config = sql_insert (iterator_string (&rows, 11));
      gchar *quoted_target = sql_insert (iterator_string (&rows, 12));
      sql ("INSERT into tasks"
           " (id, uuid, name, hidden, time, comment, description, owner,"
           "  run_status, start_time, end_time, config, target)"
           " VALUES"
           " (%llu, %s, %s, %llu, %s, %s, %s, %llu, %llu, %s,"
           "  %s, %s, %s);",
           iterator_int64 (&rows, 0),
           quoted_uuid,
           quoted_name,
           iterator_int64 (&rows, 3),
           quoted_time,
           quoted_comment,
           quoted_description,
           iterator_int64 (&rows, 7),
           iterator_int64 (&rows, 8),
           quoted_start_time,
           quoted_end_time,
           quoted_config,
           quoted_target);
      g_free (quoted_uuid);
      g_free (quoted_name);
      g_free (quoted_time);
      g_free (quoted_comment);
      g_free (quoted_description);
      g_free (quoted_start_time);
      g_free (quoted_end_time);
      g_free (quoted_config);
      g_free (quoted_target);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE tasks_4;");

  /* Table users. */
  init_iterator (&rows, "SELECT rowid, name, password FROM users_4;");
  while (next (&rows))
    {
      gchar *quoted_name = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_password = sql_insert (iterator_string (&rows, 2));
      sql ("INSERT into users (id, name, password)"
           " VALUES (%llu, %s, %s);",
           iterator_int64 (&rows, 0),
           quoted_name,
           quoted_password);
      g_free (quoted_name);
      g_free (quoted_password);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE users_4;");
}

/**
 * @brief Migrate the database from version 4 to version 5.
 *
 * @return 0 success, -1 error.
 */
int
migrate_4_to_5 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 4. */

  if (manage_db_version () != 4)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Every table got an "id INTEGER PRIMARY KEY" column.  As the column is a
   * primary key, every table must be recreated and the data transfered.
   *
   * Also, starting from revision 5726 on 2009-10-26 (just before 0.9.2),
   * the Manager converts semicolons in OTP NVT descriptions to newlines
   * before entering them in the database.  Convert the existing
   * semicolons while transfering the data.  This should have been an
   * entirely separate version and migration between the current 4 and 5. */

  /* Ensure that all tables exist that will be adjusted below. */

  /* Both introduced between version 1 and 2. */
  sql ("CREATE TABLE IF NOT EXISTS nvt_preferences (name, value);");
  sql ("CREATE TABLE IF NOT EXISTS task_files (task INTEGER, name, content);");

  /* Move the tables away. */

  sql ("ALTER TABLE config_preferences RENAME TO config_preferences_4;");
  sql ("ALTER TABLE configs RENAME TO configs_4;");
  sql ("ALTER TABLE lsc_credentials RENAME TO lsc_credentials_4;");
  sql ("ALTER TABLE meta RENAME TO meta_4;");
  sql ("ALTER TABLE nvt_preferences RENAME TO nvt_preferences_4;");
  sql ("ALTER TABLE nvt_selectors RENAME TO nvt_selectors_4;");
  sql ("ALTER TABLE nvts RENAME TO nvts_4;");
  sql ("ALTER TABLE report_hosts RENAME TO report_hosts_4;");
  sql ("ALTER TABLE report_results RENAME TO report_results_4;");
  sql ("ALTER TABLE reports RENAME TO reports_4;");
  sql ("ALTER TABLE results RENAME TO results_4;");
  sql ("ALTER TABLE targets RENAME TO targets_4;");
  sql ("ALTER TABLE task_files RENAME TO task_files_4;");
  sql ("ALTER TABLE tasks RENAME TO tasks_4;");
  sql ("ALTER TABLE users RENAME TO users_4;");

  /* Create the new tables in version 4 format. */

  create_tables_version_4 ();

  /* Copy the data into the new tables, dropping the old tables. */

  migrate_4_to_5_copy_data ();

  /* Set the database version to 5. */

  set_db_version (5);

  sql ("COMMIT;");

  /* All the moving may have left much empty space, so vacuum. */

  sql ("VACUUM;");

  return 0;
}

/**
 * @brief Move a config that is using a predefined ID.
 *
 * @param[in]  predefined_config_name  Name of the predefined config.
 * @param[in]  predefined_config_id    Row ID of the predefined config.
 */
void
migrate_5_to_6_move_other_config (const char *predefined_config_name,
                                  config_t predefined_config_id)
{
  if (sql_int (0, 0,
               "SELECT COUNT(*) = 0 FROM configs"
               " WHERE name = '%s';",
               predefined_config_name)
      && sql_int (0, 0,
                  "SELECT COUNT(*) = 1 FROM configs"
                  " WHERE ROWID = %llu;",
                  predefined_config_id))
    {
      config_t config;
      char *name;
      gchar *quoted_name;

      sql ("INSERT into configs (nvt_selector, comment, family_count,"
           " nvt_count, nvts_growing, families_growing)"
           " SELECT nvt_selector, comment, family_count,"
           " nvt_count, nvts_growing, families_growing"
           " FROM configs"
           " WHERE ROWID = %llu;",
           predefined_config_id);
      /* This ID will be larger then predefined_config_id because
       * predefined_config_id exists already.  At worst the ID will be one
       * larger. */
      config = sqlite3_last_insert_rowid (task_db);
      sql ("UPDATE config_preferences SET config = %llu WHERE config = %llu;",
           config,
           predefined_config_id);
      name = sql_string (0, 0,
                         "SELECT name FROM configs WHERE ROWID = %llu;",
                         predefined_config_id);
      if (name == NULL)
        {
          sql ("ROLLBACK;");
          abort ();
        }
      quoted_name = sql_quote (name);
      free (name);
      /* Table tasks references config by name, so it stays the same. */
      sql ("DELETE FROM configs WHERE ROWID = %llu;",
           predefined_config_id);
      sql ("UPDATE configs SET name = '%s' WHERE ROWID = %llu;",
           quoted_name,
           config);
      g_free (quoted_name);
    }
}

/**
 * @brief Migrate the database from version 5 to version 6.
 *
 * @return 0 success, -1 error.
 */
int
migrate_5_to_6 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 5. */

  if (manage_db_version () != 5)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The predefined configs got predefined ID's and the manager now also
   * caches counts for growing configs. */

  /* Fail with a message if the predefined configs have somehow got ID's
   * other than the usual ones. */

  if (sql_int (0, 0,
               "SELECT COUNT(*) = 0 OR ROWID == 1 FROM configs"
               " WHERE name = 'Full and fast';")
      && sql_int (0, 0,
                  "SELECT COUNT(*) = 0 OR ROWID == 2 FROM configs"
                  " WHERE name = 'Full and fast ultimate';")
      && sql_int (0, 0,
                  "SELECT COUNT(*) = 0 OR ROWID == 3 FROM configs"
                  " WHERE name = 'Full and very deep';")
      && sql_int (0, 0,
                  "SELECT COUNT(*) = 0 OR ROWID == 4 FROM configs"
                  " WHERE name = 'Full and very deep ultimate';"))
    {
      /* Any predefined configs are OK.  Move any other configs that have the
       * predefined ID's. */

      /* The ID of the moved config may be only one larger, so these must
       * be done in ID order. */
      migrate_5_to_6_move_other_config ("Full and fast", 1);
      migrate_5_to_6_move_other_config ("Full and fast ultimate", 2);
      migrate_5_to_6_move_other_config ("Full and very deep", 3);
      migrate_5_to_6_move_other_config ("Full and very deep ultimate", 4);
    }
  else
    {
      g_warning ("%s: a predefined config has moved from the standard location,"
                 " giving up\n",
                 __FUNCTION__);
      sql ("ROLLBACK;");
      return -1;
    }

  /* This would need a duplicate version of update_all_config_caches that
   * worked with the version 6 database.  Just let the cache be wrong.  This
   * is a very old version now. */
#if 0
  /* Update cache counts for growing configs. */

  update_all_config_caches ();
#endif

  /* Set the database version to 6. */

  set_db_version (6);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 6 to version 7.
 *
 * @return 0 success, -1 error.
 */
int
migrate_6_to_7 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 6. */

  if (manage_db_version () != 6)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Add lsc_credential column to targets table. */
  sql ("ALTER TABLE targets ADD COLUMN lsc_credential INTEGER;");
  sql ("UPDATE targets SET lsc_credential = 0;");

  /* Set the database version to 7. */

  set_db_version (7);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 7 to version 8.
 *
 * @return 0 success, -1 error.
 */
int
migrate_7_to_8 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 7. */

  if (manage_db_version () != 7)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The lsc_credentials table got a login column. */

  sql ("ALTER TABLE lsc_credentials ADD COLUMN login;");
  sql ("UPDATE lsc_credentials SET login = name;");

  /* Set the database version to 8. */

  set_db_version (8);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 8 to version 9.
 *
 * @return 0 success, -1 error.
 */
int
migrate_8_to_9 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 8. */

  if (manage_db_version () != 8)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo Does ROLLBACK happen when these fail? */

  /* Ensure that all tables that will be modified here exist.  These were
   * all added after version 8 anyway. */

  sql ("CREATE TABLE IF NOT EXISTS escalators"
       " (id INTEGER PRIMARY KEY, name UNIQUE, comment, event INTEGER,"
       "  condition INTEGER, method INTEGER);");

  sql ("CREATE TABLE IF NOT EXISTS agents"
       " (id INTEGER PRIMARY KEY, name UNIQUE, comment, installer TEXT,"
       "  howto_install TEXT, howto_use TEXT);");

  /* Many tables got an owner column. */

  sql ("ALTER TABLE targets ADD COLUMN owner INTEGER;");
  sql ("UPDATE targets SET owner = NULL;");

  sql ("ALTER TABLE configs ADD COLUMN owner INTEGER;");
  sql ("UPDATE configs SET owner = NULL;");

  sql ("ALTER TABLE lsc_credentials ADD COLUMN owner INTEGER;");
  sql ("UPDATE lsc_credentials SET owner = NULL;");

  sql ("ALTER TABLE escalators ADD COLUMN owner INTEGER;");
  sql ("UPDATE escalators SET owner = NULL;");

  sql ("ALTER TABLE reports ADD COLUMN owner INTEGER;");
  sql ("UPDATE reports SET owner = NULL;");

  sql ("ALTER TABLE agents ADD COLUMN owner INTEGER;");
  sql ("UPDATE agents SET owner = NULL;");

  /* The owner column in tasks changed type from string to int.  This
   * may be a redundant conversion, as SQLite may have converted these
   * values automatically in each query anyway. */

  sql ("UPDATE tasks SET owner = CAST (owner AS INTEGER);"),

  /* Set the database version to 9. */

  set_db_version (9);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Return the UUID of a user from the OpenVAS user UUID file.
 *
 * @todo Untested
 *
 * @param[in]  name   User name.
 *
 * @return UUID of given user if user exists, else NULL.
 */
gchar *
migrate_9_to_10_user_uuid (const char *name)
{
  gchar *uuid_file;

  uuid_file = g_build_filename (OPENVAS_STATE_DIR, "users", name, "uuid", NULL);
  if (g_file_test (uuid_file, G_FILE_TEST_EXISTS))
    {
      gsize size;
      gchar *uuid;
      /* File exists, get its content (the uuid). */
      if (g_file_get_contents (uuid_file, &uuid, &size, NULL))
        {
          if (strlen (uuid) < 36)
            g_free (uuid);
          else
            {
              g_free (uuid_file);
              /* Drop any trailing characters. */
              uuid[36] = '\0';
              return uuid;
            }
        }
    }
  g_free (uuid_file);
  return NULL;
}

/**
 * @brief Migrate the database from version 9 to version 10.
 *
 * @return 0 success, -1 error.
 */
int
migrate_9_to_10 ()
{
  iterator_t rows;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 9. */

  if (manage_db_version () != 9)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The user table got a unique "uuid" column and lost the
   * uniqueness of its "name" column. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE users RENAME TO users_9;");

  sql ("CREATE TABLE users"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, name, password);");

  init_iterator (&rows, "SELECT rowid, name, password FROM users_9;");
  while (next (&rows))
    {
      gchar *quoted_name, *quoted_password, *uuid;

      uuid = migrate_9_to_10_user_uuid (iterator_string (&rows, 1));
      if (uuid == NULL)
        {
          uuid = openvas_uuid_make ();
          if (uuid == NULL)
            {
              cleanup_iterator (&rows);
              sql ("ROLLBACK;");
              return -1;
            }
        }

      quoted_name = sql_insert (iterator_string (&rows, 1));
      quoted_password = sql_insert (iterator_string (&rows, 2));
      sql ("INSERT into users (id, uuid, name, password)"
           " VALUES (%llu, '%s', %s, %s);",
           iterator_int64 (&rows, 0),
           uuid,
           quoted_name,
           quoted_password);
      g_free (uuid);
      g_free (quoted_name);
      g_free (quoted_password);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE users_9;");

  /* Set the database version to 10. */

  set_db_version (10);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 10 to version 11.
 *
 * @return 0 success, -1 error.
 */
int
migrate_10_to_11 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 10. */

  if (manage_db_version () != 10)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The config and target columns of the tasks table changed from the name
   * of the config/target to the ROWID of the config/target.
   *
   * Recreate the table, in order to add INTEGER to the column definitions. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE tasks RENAME TO tasks_10;");

  sql ("CREATE TABLE tasks"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, hidden INTEGER,"
       "  time, comment, description, run_status INTEGER, start_time,"
       "  end_time, config INTEGER, target INTEGER);");

  sql ("INSERT into tasks"
       " (id, uuid, owner, name, hidden, time, comment, description,"
       "  run_status, start_time, end_time, config, target)"
       " SELECT"
       "  id, uuid, owner, name, hidden, time, comment, description,"
       "  run_status, start_time, end_time,"
       "  (SELECT ROWID FROM configs WHERE configs.name = tasks_10.config),"
       "  (SELECT ROWID FROM targets WHERE targets.name = tasks_10.target)"
       " FROM tasks_10;");

  sql ("DROP TABLE tasks_10;");

  /* Set the database version to 11. */

  set_db_version (11);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 11 to version 12.
 *
 * @return 0 success, -1 error.
 */
int
migrate_11_to_12 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 11. */

  if (manage_db_version () != 11)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Tables agents, configs and escalators were relieved of the UNIQUE
   * constraint on the name column.
   *
   * Recreate the tables, in order to remove the contraint. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE agents RENAME TO agents_11;");

  sql ("CREATE TABLE agents"
       " (id INTEGER PRIMARY KEY, owner INTEGER, name, comment,"
       "  installer TEXT, howto_install TEXT, howto_use TEXT);");

  sql ("INSERT into agents"
       " (id, owner, name, comment, installer, howto_install, howto_use)"
       " SELECT"
       "  id, owner, name, comment, installer, howto_install, howto_use"
       " FROM agents_11;");

  sql ("DROP TABLE agents_11;");

  sql ("ALTER TABLE configs RENAME TO configs_11;");

  sql ("CREATE TABLE configs"
       " (id INTEGER PRIMARY KEY, owner INTEGER, name, nvt_selector, comment,"
       "  family_count INTEGER, nvt_count INTEGER, families_growing INTEGER,"
       "  nvts_growing INTEGER);");

  sql ("INSERT into configs"
       " (id, owner, name, nvt_selector, comment, family_count, nvt_count,"
       "  families_growing, nvts_growing)"
       " SELECT"
       "  id, owner, name, nvt_selector, comment, family_count, nvt_count,"
       "  families_growing, nvts_growing"
       " FROM configs_11;");

  sql ("DROP TABLE configs_11;");

  sql ("ALTER TABLE escalators RENAME TO escalators_11;");

  sql ("CREATE TABLE escalators"
       " (id INTEGER PRIMARY KEY, owner INTEGER, name, comment, event INTEGER,"
       "  condition INTEGER, method INTEGER);");

  sql ("INSERT into escalators"
       " (id, owner, name, comment, event, condition, method)"
       " SELECT"
       "  id, owner, name, comment, event, condition, method"
       " FROM escalators_11;");

  sql ("DROP TABLE escalators_11;");

  /* Set the database version to 12. */

  set_db_version (12);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 12 to version 13.
 *
 * @return 0 success, -1 error.
 */
int
migrate_12_to_13 ()
{
  iterator_t rows;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 12. */

  if (manage_db_version () != 12)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Table nvt_selectors column name changed to a UUID.
   *
   * Replace names with UUIDs, ensuring that the 'All' selector gets the
   * predefined UUID. */

  /** @todo ROLLBACK on failure. */

  init_iterator (&rows, "SELECT distinct name FROM nvt_selectors;");
  while (next (&rows))
    {
      gchar *quoted_name, *uuid;

      if (strcmp (iterator_string (&rows, 0), "All") == 0)
        continue;

      uuid = openvas_uuid_make ();
      if (uuid == NULL)
        {
          cleanup_iterator (&rows);
          sql ("ROLLBACK;");
          return -1;
        }

      quoted_name = sql_insert (iterator_string (&rows, 0));

      sql ("UPDATE nvt_selectors SET name = '%s' WHERE name = %s;",
           uuid,
           quoted_name);

      sql ("UPDATE configs SET nvt_selector = '%s' WHERE nvt_selector = %s;",
           uuid,
           quoted_name);

      g_free (uuid);
      g_free (quoted_name);
    }
  cleanup_iterator (&rows);

  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM nvt_selectors WHERE name = '"
               MANAGE_NVT_SELECTOR_UUID_ALL "';"))
    sql ("DELETE FROM nvt_selectors WHERE name = 'All';");
  else
    sql ("UPDATE nvt_selectors"
         " SET name = '" MANAGE_NVT_SELECTOR_UUID_ALL "'"
         " WHERE name = 'All';");

  sql ("UPDATE configs"
       " SET nvt_selector = '" MANAGE_NVT_SELECTOR_UUID_ALL "'"
       " WHERE nvt_selector = 'All';");

  /* Set the database version to 13. */

  set_db_version (13);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 13 to version 14.
 *
 * @return 0 success, -1 error.
 */
int
migrate_13_to_14 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 13. */

  if (manage_db_version () != 13)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Table results got a UUID column. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE results ADD COLUMN uuid;");
  sql ("UPDATE results SET uuid = make_uuid();");

  /* Set the database version to 14. */

  set_db_version (14);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 14 to version 15.
 *
 * @return 0 success, -1 error.
 */
int
migrate_14_to_15 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 14. */

  if (manage_db_version () != 14)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Table tasks got columns for scheduling info. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE tasks ADD COLUMN schedule INTEGER;");
  sql ("ALTER TABLE tasks ADD COLUMN schedule_next_time;");
  sql ("UPDATE tasks SET schedule = 0, schedule_next_time = 0;");

  /* Set the database version to 15. */

  set_db_version (15);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 15 to version 16.
 *
 * @return 0 success, -1 error.
 */
int
migrate_15_to_16 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 15. */

  if (manage_db_version () != 15)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Table schedules got a period_months column. */

  /** @todo ROLLBACK on failure. */

  sql ("CREATE TABLE IF NOT EXISTS schedules"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment,"
       "  first_time, period, duration);");

  sql ("ALTER TABLE schedules ADD COLUMN period_months;");
  sql ("UPDATE schedules SET period_months = 0;");

  /* GSA was hardcoded to set the comment to "comment" before revision 7157,
   * so clear all task comments here. */

  sql ("UPDATE tasks SET comment = '';");

  /* Set the database version to 16. */

  set_db_version (16);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 16 to version 17.
 *
 * @return 0 success, -1 error.
 */
int
migrate_16_to_17 ()
{
  iterator_t rows;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 16. */

  if (manage_db_version () != 16)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Table nvts got columns for CVSS base and risk factor. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE nvts ADD COLUMN cvss_base;");
  sql ("ALTER TABLE nvts ADD COLUMN risk_factor;");

  /* Move the CVSS and risk values out of any existing tags. */

  init_iterator (&rows, "SELECT ROWID, tag FROM nvts;");
  while (next (&rows))
    {
      gchar *tags, *cvss_base, *risk_factor;

      parse_tags (iterator_string (&rows, 1), &tags, &cvss_base, &risk_factor);

      sql ("UPDATE nvts SET cvss_base = '%s', risk_factor = '%s', tag = '%s'"
           " WHERE ROWID = %llu;",
           cvss_base ? cvss_base : "",
           risk_factor ? risk_factor : "",
           tags ? tags : "",
           iterator_int64 (&rows, 0));

      g_free (tags);
      g_free (cvss_base);
      g_free (risk_factor);
    }
  cleanup_iterator (&rows);

  /* Set the database version to 17. */

  set_db_version (17);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Set the pref for migrate_17_to_18.
 *
 * @param[in]  config  Config to set pref on.
 */
void
migrate_17_to_18_set_pref (config_t config)
{
  if (sql_int (0, 0,
               "SELECT count(*) FROM config_preferences"
               " WHERE config = %llu"
               " AND name ="
               " 'Ping Host[checkbox]:Mark unrechable Hosts as dead"
               " (not scanning)'",
               config)
      == 0)
    sql ("INSERT into config_preferences (config, type, name, value)"
         " VALUES (%llu, 'PLUGINS_PREFS',"
         " 'Ping Host[checkbox]:Mark unrechable Hosts as dead (not scanning)',"
         " 'yes');",
         config);
}

/**
 * @brief Migrate the database from version 17 to version 18.
 *
 * @return 0 success, -1 error.
 */
int
migrate_17_to_18 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 17. */

  if (manage_db_version () != 17)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* NVT "Ping Host" was added to the predefined configs, with the
   * "Mark unrechable..." preference set to "yes". */

  /** @todo ROLLBACK on failure. */

  /* Add "Ping Host" to the "All" NVT selector. */

  if (sql_int (0, 0,
               "SELECT count(*) FROM nvt_selectors WHERE name ="
               " '" MANAGE_NVT_SELECTOR_UUID_ALL "'"
               " AND family_or_nvt = '1.3.6.1.4.1.25623.1.0.100315';")
      == 0)
    {
      sql ("INSERT into nvt_selectors"
           " (name, exclude, type, family_or_nvt, family)"
           " VALUES ('" MANAGE_NVT_SELECTOR_UUID_ALL "', 0, "
           G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
           /* OID of the "Ping Host" NVT. */
           " '1.3.6.1.4.1.25623.1.0.100315', 'Port scanners');");
    }

  /* Ensure the preference is set on the predefined configs. */

  migrate_17_to_18_set_pref (CONFIG_ID_FULL_AND_FAST);
  migrate_17_to_18_set_pref (CONFIG_ID_FULL_AND_FAST_ULTIMATE);
  migrate_17_to_18_set_pref (CONFIG_ID_FULL_AND_VERY_DEEP);
  migrate_17_to_18_set_pref (CONFIG_ID_FULL_AND_VERY_DEEP_ULTIMATE);

  /* Set the database version to 18. */

  set_db_version (18);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 18 to version 19.
 *
 * @return 0 success, -1 error.
 */
int
migrate_18_to_19 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 18. */

  if (manage_db_version () != 18)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Many tables got a unique UUID column.  As a result the predefined
   * configs and target got fixed UUIDs.
   *
   * Recreate the tables, in order to add the unique contraint. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE agents RENAME TO agents_18;");

  sql ("CREATE TABLE agents"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  installer TEXT, howto_install TEXT, howto_use TEXT);");

  sql ("INSERT into agents"
       " (id, uuid, owner, name, comment, installer, howto_install, howto_use)"
       " SELECT"
       "  id, make_uuid (), owner, name, comment, installer, howto_install, howto_use"
       " FROM agents_18;");

  sql ("DROP TABLE agents_18;");

  sql ("ALTER TABLE configs RENAME TO configs_18;");

  sql ("CREATE TABLE configs"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name,"
       "  nvt_selector, comment, family_count INTEGER, nvt_count INTEGER,"
       "  families_growing INTEGER, nvts_growing INTEGER);");

  sql ("INSERT into configs"
       " (id, uuid, owner, name, nvt_selector, comment, family_count,"
       "  nvt_count, families_growing, nvts_growing)"
       " SELECT"
       "  id, make_uuid (), owner, name, nvt_selector, comment, family_count,"
       "  nvt_count, families_growing, nvts_growing"
       " FROM configs_18;");

  sql ("DROP TABLE configs_18;");

  sql ("ALTER TABLE escalators RENAME TO escalators_18;");

  sql ("CREATE TABLE escalators"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  event INTEGER, condition INTEGER, method INTEGER);");

  sql ("INSERT into escalators"
       " (id, uuid, owner, name, comment, event, condition, method)"
       " SELECT"
       "  id, make_uuid (), owner, name, comment, event, condition, method"
       " FROM escalators_18;");

  sql ("DROP TABLE escalators_18;");

  sql ("ALTER TABLE lsc_credentials RENAME TO lsc_credentials_18;");

  sql ("CREATE TABLE lsc_credentials"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, login,"
       "  password, comment, public_key TEXT, private_key TEXT, rpm TEXT,"
       "  deb TEXT, exe TEXT);");

  sql ("INSERT into lsc_credentials"
       " (id, uuid, owner, name, login, password, comment, public_key,"
       "  private_key, rpm, deb, exe)"
       " SELECT"
       "  id, make_uuid (), owner, name, login, password, comment, public_key,"
       "  private_key, rpm, deb, exe"
       " FROM lsc_credentials_18;");

  sql ("DROP TABLE lsc_credentials_18;");

  sql ("ALTER TABLE targets RENAME TO targets_18;");

  sql ("CREATE TABLE targets"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, hosts,"
       "  comment, lsc_credential INTEGER);");

  sql ("INSERT into targets"
       " (id, uuid, owner, name, hosts, comment, lsc_credential)"
       " SELECT"
       "  id, make_uuid (), owner, name, hosts, comment, lsc_credential"
       " FROM targets_18;");

  sql ("DROP TABLE targets_18;");

  /* Set the new predefined UUIDs. */

  sql ("UPDATE configs"
       " SET uuid = '" CONFIG_UUID_FULL_AND_FAST "'"
       " WHERE ROWID = " G_STRINGIFY (CONFIG_ID_FULL_AND_FAST) ";");

  sql ("UPDATE configs"
       " SET uuid = '" CONFIG_UUID_FULL_AND_FAST_ULTIMATE "'"
       " WHERE ROWID = " G_STRINGIFY (CONFIG_ID_FULL_AND_FAST_ULTIMATE) ";");

  sql ("UPDATE configs"
       " SET uuid = '" CONFIG_UUID_FULL_AND_VERY_DEEP "'"
       " WHERE ROWID = " G_STRINGIFY (CONFIG_ID_FULL_AND_VERY_DEEP) ";");

  sql ("UPDATE configs"
       " SET uuid = '" CONFIG_UUID_FULL_AND_VERY_DEEP_ULTIMATE "'"
       " WHERE ROWID = "
       G_STRINGIFY (CONFIG_ID_FULL_AND_VERY_DEEP_ULTIMATE) ";");

  sql ("UPDATE configs"
       " SET uuid = '" CONFIG_UUID_EMPTY "'"
       " WHERE name = 'empty';");

  sql ("UPDATE targets"
       " SET uuid = '" TARGET_UUID_LOCALHOST "'"
       " WHERE name = 'Localhost';");

  /* Set the database version to 19. */

  set_db_version (19);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 19 to version 20.
 *
 * @return 0 success, -1 error.
 */
int
migrate_19_to_20 ()
{
  iterator_t rows;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 19. */

  if (manage_db_version () != 19)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The agents table got new columns.  In particular the installer column
   * moved to installer_64 and the table got a new installer column with the
   * plain installer. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE agents ADD COLUMN installer_64 TEXT;");
  sql ("ALTER TABLE agents ADD COLUMN installer_signature_64 TEXT;");
  sql ("ALTER TABLE agents ADD COLUMN installer_trust INTEGER;");

  init_iterator (&rows, "SELECT ROWID, installer FROM agents;");
  while (next (&rows))
    {
      const char *tail, *installer_64 = iterator_string (&rows, 1);
      gchar *installer, *formatted;
      gsize installer_size;
      int ret;
      sqlite3_stmt* stmt;

      sql ("UPDATE agents SET"
           " installer_trust = %i,"
           " installer_64 = installer,"
           " installer_signature_64 = ''"
           " WHERE ROWID = %llu",
           TRUST_UNKNOWN,
           iterator_int64 (&rows, 0));

      formatted = g_strdup_printf ("UPDATE agents SET installer = $installer"
                                   " WHERE ROWID = %llu;",
                                   iterator_int64 (&rows, 0));

      /* Prepare statement. */

      while (1)
        {
          ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
          if (ret == SQLITE_BUSY) continue;
          g_free (formatted);
          if (ret == SQLITE_OK)
            {
              if (stmt == NULL)
                {
                  g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                             __FUNCTION__,
                             sqlite3_errmsg (task_db));
                  cleanup_iterator (&rows);
                  sql ("ROLLBACK;");
                  return -1;
                }
              break;
            }
          g_warning ("%s: sqlite3_prepare failed: %s\n",
                     __FUNCTION__,
                     sqlite3_errmsg (task_db));
          cleanup_iterator (&rows);
          sql ("ROLLBACK;");
          return -1;
        }

      if (strlen (installer_64) > 0)
        installer = (gchar*) g_base64_decode (installer_64, &installer_size);
      else
        {
          installer = g_strdup ("");
          installer_size = 0;
        }

      /* Bind the packages to the "$values" in the SQL statement. */

      while (1)
        {
          ret = sqlite3_bind_text (stmt,
                                   1,
                                   installer,
                                   installer_size,
                                   SQLITE_TRANSIENT);
          if (ret == SQLITE_BUSY) continue;
          if (ret == SQLITE_OK) break;
          g_warning ("%s: sqlite3_prepare failed: %s\n",
                     __FUNCTION__,
                     sqlite3_errmsg (task_db));
          cleanup_iterator (&rows);
          sql ("ROLLBACK;");
          g_free (installer);
          return -1;
        }
      g_free (installer);

      /* Run the statement. */

      while (1)
        {
          ret = sqlite3_step (stmt);
          if (ret == SQLITE_BUSY) continue;
          if (ret == SQLITE_DONE) break;
          if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
            {
              if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
              g_warning ("%s: sqlite3_step failed: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              cleanup_iterator (&rows);
              sql ("ROLLBACK;");
              return -1;
            }
        }

      sqlite3_finalize (stmt);
    }
  cleanup_iterator (&rows);

  /* Set the database version to 20. */

  set_db_version (20);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 20 to version 21.
 *
 * @return 0 success, -1 error.
 */
int
migrate_20_to_21 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 20. */

  if (manage_db_version () != 20)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The agents table got an installer_filename columns. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE agents ADD COLUMN installer_filename TEXT;");

  /* Set the database version to 21. */

  set_db_version (21);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the report formats from version 21 to version 22.
 *
 * @return 0 success, -1 error.
 */
int
migrate_21_to_22 ()
{
  iterator_t rows;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 21. */

  if (manage_db_version () != 21)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the report formats.
   *
   * The name of the report format directories on disk changed from the report
   * format name to the report format UUID. */

  /** @todo ROLLBACK on failure. */

  /* Ensure that the report_formats table exists. */

  sql ("CREATE TABLE IF NOT EXISTS report_formats"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, extension,"
       "  content_type, summary, description);");

  /* Ensure that the predefined formats all exist in the database. */

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'CPE';")
      == 0)
    sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
         " extension, content_type)"
         " VALUES (make_uuid (), NULL, 'CPE',"
         " 'Common Product Enumeration CSV table.',"
         " 'CPE stands for Common Product Enumeration.  It is a structured naming scheme for\n"
         "information technology systems, platforms, and packages.  In other words: CPE\n"
         "provides a unique identifier for virtually any software product that is known for\n"
         "a vulnerability.\n"
         "\n"
         "The CPE dictionary is maintained by MITRE and NIST.  MITRE also maintains CVE\n"
         "(Common Vulnerability Enumeration) and other relevant security standards.\n"
         "\n"
         "The report selects all CPE tables from the results and forms a single table\n"
         "as a comma separated values file.\n',"
         " 'csv', 'text/csv');");

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'HTML';")
      == 0)
    sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
         " extension, content_type)"
         " VALUES (make_uuid (), NULL, 'HTML', 'Single page HTML report.',"
         " 'A single HTML page listing results of a scan.  Style information is embedded in\n"
         "the HTML, so the page is suitable for viewing in a browser as is.\n',"
         " 'html', 'text/html');");

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'ITG';")
      == 0)
    sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
         " extension, content_type)"
         " VALUES (make_uuid (), NULL, 'ITG',"
         " 'German \"IT-Grundschutz-Kataloge\" report.',"
         " 'Tabular report on the German \"IT-Grundschutz-Kataloge\",\n"
         "as published and maintained by the German Federal Agency for IT-Security.\n',"
         " 'csv', 'text/csv');");

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'LaTeX';")
      == 0)
    sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
         " extension, content_type)"
         " VALUES (make_uuid (), NULL, 'LaTeX',"
         " 'LaTeX source file.',"
         " 'Report as LaTeX source file for further processing.\n',"
         " 'tex', 'text/plain');");

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'NBE';")
      == 0)
    sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
         " extension, content_type)"
         " VALUES (make_uuid (), NULL, 'NBE', 'Legacy OpenVAS report.',"
         " 'The traditional OpenVAS Scanner text based format.',"
         " 'nbe', 'text/plain');");

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'PDF';")
      == 0)
    sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
         " extension, content_type)"
         " VALUES (make_uuid (), NULL, 'PDF',"
         " 'Portable Document Format report.',"
         " 'Scan results in Portable Document Format (PDF).',"
         "'pdf', 'application/pdf');");

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'TXT';")
      == 0)
    sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
         " extension, content_type)"
         " VALUES (make_uuid (), NULL, 'TXT', 'Plain text report.',"
         " 'Plain text report, best viewed with fixed font size.',"
         " 'txt', 'text/plain');");

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'XML';")
      == 0)
    sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
         " extension, content_type)"
         " VALUES (make_uuid (), NULL, 'XML',"
         " 'Raw XML report.',"
         " 'Complete scan report in OpenVAS Manager XML format.',"
         " 'xml', 'text/xml');");

  /* Update the UUIDs of the predefined formats to the new predefined UUIDs. */

  sql ("UPDATE report_formats SET uuid = 'a0704abb-2120-489f-959f-251c9f4ffebd'"
       " WHERE name = 'CPE'");

  sql ("UPDATE report_formats SET uuid = 'b993b6f5-f9fb-4e6e-9c94-dd46c00e058d'"
       " WHERE name = 'HTML'");

  sql ("UPDATE report_formats SET uuid = '929884c6-c2c4-41e7-befb-2f6aa163b458'"
       " WHERE name = 'ITG'");

  sql ("UPDATE report_formats SET uuid = '9f1ab17b-aaaa-411a-8c57-12df446f5588'"
       " WHERE name = 'LaTeX'");

  sql ("UPDATE report_formats SET uuid = 'f5c2a364-47d2-4700-b21d-0a7693daddab'"
       " WHERE name = 'NBE'");

  sql ("UPDATE report_formats SET uuid = '1a60a67e-97d0-4cbf-bc77-f71b08e7043d'"
       " WHERE name = 'PDF'");

  sql ("UPDATE report_formats SET uuid = '19f6f1b3-7128-4433-888c-ccc764fe6ed5'"
       " WHERE name = 'TXT'");

  sql ("UPDATE report_formats SET uuid = 'd5da9f67-8551-4e51-807b-b6a873d70e34'"
       " WHERE name = 'XML'");

  /* Rename the directories. */

  init_iterator (&rows, "SELECT ROWID, uuid, owner, name FROM report_formats;");
  while (next (&rows))
    {
      const char *name, *uuid;
      gchar *old_dir, *new_dir;
      int user_format = 0;

      uuid = iterator_string (&rows, 1);
      name = iterator_string (&rows, 3);

      if (sql_int (0, 0,
                   "SELECT owner is NULL FROM report_formats"
                   " WHERE ROWID = %llu;",
                   iterator_int64 (&rows, 0)))
        {
          /* Global. */
          old_dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                                      "openvasmd",
                                      "global_report_formats",
                                      name,
                                      NULL);
          new_dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                                      "openvasmd",
                                      "global_report_formats",
                                      uuid,
                                      NULL);
        }
      else
        {
          char *owner_uuid;
          owner_uuid = sql_string (0, 0,
                                   "SELECT uuid FROM users"
                                   " WHERE ROWID = %llu;",
                                   iterator_int64 (&rows, 2));
          if (owner_uuid == NULL)
            {
              g_warning ("%s: owner missing from users table\n", __FUNCTION__);
              cleanup_iterator (&rows);
              sql ("ROLLBACK;");
              return -1;
            }
          old_dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                                      "openvasmd",
                                      "report_formats",
                                      owner_uuid,
                                      name,
                                      NULL);
          new_dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                                      "openvasmd",
                                      "report_formats",
                                      owner_uuid,
                                      uuid,
                                      NULL);
          free (owner_uuid);
          user_format = 1;
        }
      if (g_file_test (new_dir, G_FILE_TEST_EXISTS))
        {
          if (g_file_test (old_dir, G_FILE_TEST_EXISTS)
              && openvas_file_remove_recurse (old_dir))
            g_warning ("%s: failed to remove %s\n",
                       __FUNCTION__,
                       old_dir);
        }
      /* If the old dir of a predefined format is missing that's OK, the
       * Manager will create the dir when it starts proper. */
      else if ((g_file_test (old_dir, G_FILE_TEST_EXISTS)
                || user_format)
               && rename (old_dir, new_dir))
        {
          g_warning ("%s: renaming %s to %s failed: %s\n",
                     __FUNCTION__,
                     old_dir,
                     new_dir,
                     strerror (errno));
          g_free (old_dir);
          g_free (new_dir);
          cleanup_iterator (&rows);
          sql ("ROLLBACK;");
          return -1;
        }
      g_free (old_dir);
      g_free (new_dir);
    }

  /* Set the database version to 22. */

  set_db_version (22);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the report formats from version 22 to version 23.
 *
 * @return 0 success, -1 error.
 */
int
migrate_22_to_23 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 22. */

  if (manage_db_version () != 22)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the report formats.
   *
   * The report_formats table got signature and trust columns. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE report_formats ADD COLUMN signature;");
  sql ("UPDATE report_formats SET signature = '';");

  sql ("ALTER TABLE report_formats ADD COLUMN trust;");
  sql ("UPDATE report_formats SET trust = %i;", TRUST_UNKNOWN);

  /* Set the database version to 23. */

  set_db_version (23);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 23 to version 24.
 *
 * @return 0 success, -1 error.
 */
int
migrate_23_to_24 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 23. */

  if (manage_db_version () != 23)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The 8 to 9 migrator cast owner to an integer because owner had
   * changed from a string to an integer.  This means empty strings would
   * be converted to 0 instead of NULL, so convert any 0's to NULL. */

  sql ("UPDATE tasks SET owner = NULL where owner = 0;"),

  /* Set the database version to 24. */

  set_db_version (24);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 24 to version 25.
 *
 * @return 0 success, -1 error.
 */
int
migrate_24_to_25 ()
{
  iterator_t rows;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 24. */

  if (manage_db_version () != 24)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Missing parameter chunking handling in the GSA may have resulted in
   * empty options in NVT radio preference values. */

  init_iterator (&rows, "SELECT ROWID, name, value FROM nvt_preferences;");
  while (next (&rows))
    {
      const char *name;
      int type_start = -1, type_end = -1, count;

      name = iterator_string (&rows, 1);

      /* NVT[radio]:Preference */
      count = sscanf (name, "%*[^[][%nradio%n]:", &type_start, &type_end);
      if (count == 0 && type_start > 0 && type_end > 0)
        {
          const char *value;
          gchar **split, **point, *quoted_value;
          GString *string;
          gboolean first;

          /* Flush any empty options (";a;;b;" becomes "a;b"). */
          first = TRUE;
          value = iterator_string (&rows, 2);
          split = g_strsplit (value, ";", 0);
          string = g_string_new ("");
          point = split;
          while (*point)
            {
              if (strlen (*point))
                {
                  if (first)
                    first = FALSE;
                  else
                    g_string_append_c (string, ';');
                  g_string_append (string, *point);
                }
              point++;
            }
          g_strfreev (split);

          quoted_value = sql_nquote (string->str, string->len);
          g_string_free (string, TRUE);
          sql ("UPDATE nvt_preferences SET value = '%s' WHERE ROWID = %llu",
               quoted_value,
               iterator_int64 (&rows, 0));
          g_free (quoted_value);
        }
    }
  cleanup_iterator (&rows);

  init_iterator (&rows,
                 "SELECT ROWID, name, value FROM config_preferences"
                 " WHERE type = 'PLUGINS_PREFS';");
  while (next (&rows))
    {
      const char *name;
      int type_start = -1, type_end = -1, count;

      name = iterator_string (&rows, 1);

      /* NVT[radio]:Preference */
      count = sscanf (name, "%*[^[][%nradio%n]:", &type_start, &type_end);
      if (count == 0 && type_start > 0 && type_end > 0)
        {
          const char *value;
          gchar **split, **point, *quoted_value;
          GString *string;
          gboolean first;

          /* Flush any empty options (";a;;b;" becomes "a;b"). */
          first = TRUE;
          value = iterator_string (&rows, 2);
          split = g_strsplit (value, ";", 0);
          string = g_string_new ("");
          point = split;
          while (*point)
            {
              if (strlen (*point))
                {
                  if (first)
                    first = FALSE;
                  else
                    g_string_append_c (string, ';');
                  g_string_append (string, *point);
                }
              point++;
            }
          g_strfreev (split);

          quoted_value = sql_nquote (string->str, string->len);
          g_string_free (string, TRUE);
          sql ("UPDATE config_preferences SET value = '%s' WHERE ROWID = %llu",
               quoted_value,
               iterator_int64 (&rows, 0));
          g_free (quoted_value);
        }
    }
  cleanup_iterator (&rows);

  /* Set the database version to 25. */

  set_db_version (25);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 25 to version 26.
 *
 * @return 0 success, -1 error.
 */
int
migrate_25_to_26 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 25. */

  if (manage_db_version () != 25)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The report_formats table got a trust_time column. */

  sql ("ALTER TABLE report_formats ADD column trust_time;");
  sql ("UPDATE report_formats SET trust_time = %i;", time (NULL));

  /* Set the database version to 26. */

  set_db_version (26);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 26 to version 27.
 *
 * @return 0 success, -1 error.
 */
int
migrate_26_to_27 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 26. */

  if (manage_db_version () != 26)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The reports table got a slave_progress column and the tasks table got a
   * slave column. */

  sql ("ALTER TABLE reports ADD column slave_progress;");
  sql ("UPDATE reports SET slave_progress = 0;");

  sql ("ALTER TABLE tasks ADD column slave;");
  sql ("UPDATE tasks SET slave = 0;");

  /* Set the database version to 27. */

  set_db_version (27);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 27 to version 28.
 *
 * @return 0 success, -1 error.
 */
int
migrate_27_to_28 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 27. */

  if (manage_db_version () != 27)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The report_formats table got a flags column. */

  sql ("ALTER TABLE report_formats ADD COLUMN flags INTEGER;");
  sql ("UPDATE report_formats SET flags = 1;");

  /* Set the database version to 28. */

  set_db_version (28);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 27 to version 28.
 *
 * @return 0 success, -1 error.
 */
int
migrate_28_to_29 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 28. */

  if (manage_db_version () != 28)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The reports table got a slave_task_uuid column. */

  sql ("ALTER TABLE reports ADD COLUMN slave_task_uuid;");
  sql ("UPDATE reports SET slave_task_uuid = ''");

  /* Set the database version to 29. */

  set_db_version (29);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 29 to version 30.
 *
 * @return 0 success, -1 error.
 */
int
migrate_29_to_30 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 29. */

  if (manage_db_version () != 29)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The agents table got an installer_trust_time column. */

  sql ("ALTER TABLE agents ADD column installer_trust_time;");
  sql ("UPDATE agents SET installer_trust_time = %i;", time (NULL));

  /* Set the database version to 30. */

  set_db_version (30);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 30 to version 31.
 *
 * @return 0 success, -1 error.
 */
int
migrate_30_to_31 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 30. */

  if (manage_db_version () != 30)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Slaves switched from being targets to being resources of their own.
   * Just clear any task slaves. */

  sql ("UPDATE tasks SET slave = 0;");

  /* Set the database version to 31. */

  set_db_version (31);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 31 to version 32.
 *
 * @return 0 success, -1 error.
 */
int
migrate_31_to_32 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 31. */

  if (manage_db_version () != 31)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Ensure that the report_format_params table exists. */

  sql ("CREATE TABLE IF NOT EXISTS report_format_params"
       " (id INTEGER PRIMARY KEY, report_format, name, value);");

  /* The report_format_params table got a type column. */

  sql ("ALTER TABLE report_format_params ADD column type INTEGER;");
  sql ("UPDATE report_format_params SET type = 3;");

  /* Set the database version to 32. */

  set_db_version (32);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 32 to version 33.
 *
 * @return 0 success, -1 error.
 */
int
migrate_32_to_33 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 32. */

  if (manage_db_version () != 32)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The report_format_params table got a few new columns. */

  sql ("ALTER TABLE report_format_params ADD column type_min;");
  sql ("UPDATE report_format_params SET type_min = %lli;", LLONG_MIN);

  sql ("ALTER TABLE report_format_params ADD column type_max;");
  sql ("UPDATE report_format_params SET type_max = %lli;", LLONG_MAX);

  sql ("ALTER TABLE report_format_params ADD column type_regex;");
  sql ("UPDATE report_format_params SET type_regex = '';");

  sql ("ALTER TABLE report_format_params ADD column fallback;");
  sql ("UPDATE report_format_params SET fallback = value;");

  /* Set the database version to 33. */

  set_db_version (33);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Set the pref for migrate_33_to_34.
 *
 * @param[in]  config  Config to set pref on.
 */
void
migrate_33_to_34_set_pref (config_t config)
{
  if (sql_int (0, 0,
               "SELECT count(*) FROM config_preferences"
               " WHERE config = %llu"
               " AND name ="
               " 'Login configurations[checkbox]:NTLMSSP';",
               config)
      == 0)
    sql ("INSERT into config_preferences (config, type, name, value)"
         " VALUES (%llu, 'PLUGINS_PREFS',"
         " 'Login configurations[checkbox]:NTLMSSP',"
         " 'yes');",
         config);
}

/**
 * @brief Migrate the database from version 33 to version 34.
 *
 * @return 0 success, -1 error.
 */
int
migrate_33_to_34 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 33. */

  if (manage_db_version () != 33)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The preference "NTLMSSP" was set to yes in the predefined configs. */

  /** @todo ROLLBACK on failure. */

  migrate_33_to_34_set_pref (CONFIG_ID_FULL_AND_FAST);
  migrate_33_to_34_set_pref (CONFIG_ID_FULL_AND_FAST_ULTIMATE);
  migrate_33_to_34_set_pref (CONFIG_ID_FULL_AND_VERY_DEEP);
  migrate_33_to_34_set_pref (CONFIG_ID_FULL_AND_VERY_DEEP_ULTIMATE);

  /* Set the database version to 34. */

  set_db_version (34);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 34 to version 35.
 *
 * @return 0 success, -1 error.
 */
int
migrate_34_to_35 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 34. */

  if (manage_db_version () != 34)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The LSC credential element of the target resource was split into two
   * elements, for SSH and SMB. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE targets ADD column smb_lsc_credential;");
  sql ("UPDATE targets SET smb_lsc_credential = lsc_credential;");

  /* Set the database version to 35. */

  set_db_version (35);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Make a copy of a target.
 *
 * @param[in]  target  Target to copy.
 * @param[in]  name    Name for new target.
 *
 * @return Address of matching character, else NULL.
 */
target_t
migrate_35_to_36_duplicate_target (target_t target, const char *name)
{
  char *quoted_name = sql_quote (name);
  sql ("INSERT INTO targets"
       " (uuid, owner, name, hosts, comment, lsc_credential,"
       "  smb_lsc_credential)"
       " SELECT make_uuid (), owner, uniquify ('target', '%s', owner, ''),"
       "        hosts, comment, lsc_credential, smb_lsc_credential"
       " FROM targets WHERE ROWID = %llu;",
       quoted_name,
       target);
  g_free (quoted_name);
  return sqlite3_last_insert_rowid (task_db);
}

/**
 * @brief Migrate the database from version 35 to version 36.
 *
 * @return 0 success, -1 error.
 */
int
migrate_35_to_36 ()
{
  iterator_t tasks;
  char *scanner_range, *quoted_scanner_range;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 35. */

  if (manage_db_version () != 35)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* For a time between 1.0.0 beta3 and 1.0.0 beta5 the Manager would create
   * the example task with name references to the target and config, instead
   * of ID references.  Correct this now. */

  sql ("UPDATE tasks SET"
       " target = (SELECT ROWID FROM targets WHERE name = 'Localhost'),"
       " config = (SELECT ROWID FROM configs WHERE name = 'Full and fast')"
       " WHERE uuid = '" MANAGE_EXAMPLE_TASK_UUID "';");

  /* Scanner preference "port_range" moved from config into target. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE targets ADD column port_range;");
  sql ("UPDATE targets SET port_range = NULL;");

  scanner_range = sql_string (0, 0,
                              "SELECT value FROM nvt_preferences"
                              " WHERE name = 'port_range'");
  if (scanner_range)
    {
      quoted_scanner_range = sql_quote (scanner_range);
      free (scanner_range);
    }
  else
    quoted_scanner_range = NULL;

  init_iterator (&tasks, "SELECT ROWID, target, config FROM tasks;");
  while (next (&tasks))
    {
      char *config_range, *quoted_config_range;
      target_t target;

      target = iterator_int64 (&tasks, 1);

      if (sql_int (0, 0,
                   "SELECT port_range IS NULL FROM targets WHERE ROWID = %llu;",
                   target)
          == 0)
        {
          gchar *name;

          /* Already used this target, use a copy of it. */

          name = sql_string (0, 0,
                             "SELECT name || ' Migration' FROM targets"
                             " WHERE ROWID = %llu;",
                             target);
          assert (name);
          target = migrate_35_to_36_duplicate_target (target, name);
          free (name);

          sql ("UPDATE tasks SET target = %llu WHERE ROWID = %llu",
               target,
               iterator_int64 (&tasks, 0));
        }

      config_range = sql_string (0, 0,
                                 "SELECT value FROM config_preferences"
                                 " WHERE config = %llu"
                                 " AND name = 'port_range';",
                                 iterator_int64 (&tasks, 2));

      if (config_range)
        {
          quoted_config_range = sql_quote (config_range);
          free (config_range);
        }
      else
        quoted_config_range = NULL;

      sql ("UPDATE targets SET port_range = '%s'"
           " WHERE ROWID = %llu;",
           quoted_config_range
            ? quoted_config_range
            : (quoted_scanner_range ? quoted_scanner_range : "default"),
           target);

      free (quoted_config_range);
    }
  cleanup_iterator (&tasks);

  sql ("UPDATE targets SET port_range = 'default' WHERE port_range IS NULL;");

  sql ("DELETE FROM config_preferences WHERE name = 'port_range';");
  sql ("DELETE FROM nvt_preferences WHERE name = 'port_range';");

  free (quoted_scanner_range);

  /* Set the database version to 36. */

  set_db_version (36);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 36 to version 37.
 *
 * @return 0 success, -1 error.
 */
int
migrate_36_to_37 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 36. */

  if (manage_db_version () != 36)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The target and config clauses were swapped in the example task statement
     in migrate_35_to_36 in SVN for some time.  Run the statement again with
     the correct clauses. */

  sql ("UPDATE tasks SET"
       " target = (SELECT ROWID FROM targets WHERE name = 'Localhost'),"
       " config = (SELECT ROWID FROM configs WHERE name = 'Full and fast')"
       " WHERE uuid = '" MANAGE_EXAMPLE_TASK_UUID "';");

  /* Set the database version to 37. */

  set_db_version (37);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 37 to version 38.
 *
 * @return 0 success, -1 error.
 */
int
migrate_37_to_38 ()
{
  gchar *old_dir, *new_dir;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 37. */

  if (manage_db_version () != 37)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The report formats moved to FHS compliant locations. */

  /* Remove the global report format dirs, as they should have been
   * installed in the new location already. */

  old_dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                              "openvasmd",
                              "global_report_formats",
                              NULL);

  openvas_file_remove_recurse (old_dir);
  g_free (old_dir);

  /* Move user uploaded report formats. */

  new_dir = g_build_filename (OPENVAS_STATE_DIR,
                              "openvasmd",
                              NULL);

  if (g_mkdir_with_parents (new_dir, 0755 /* "rwxr-xr-x" */))
    {
      g_warning ("%s: failed to create dir %s", __FUNCTION__, new_dir);
      g_free (new_dir);
      sql ("ROLLBACK;");
      return -1;
    }

  old_dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                              "openvasmd",
                              "report_formats",
                              NULL);

  /* Ensure the old dir exists. */
  g_mkdir_with_parents (old_dir, 0755 /* "rwxr-xr-x" */);

  {
    gchar **cmd;
    gchar *standard_out = NULL;
    gchar *standard_err = NULL;
    gint exit_status;

    cmd = (gchar **) g_malloc (4 * sizeof (gchar *));
    cmd[0] = g_strdup ("mv");
    cmd[1] = old_dir;
    cmd[2] = new_dir;
    cmd[3] = NULL;
    g_debug ("%s: Spawning in .: %s %s %s\n",
             __FUNCTION__, cmd[0], cmd[1], cmd[2]);
    if ((g_spawn_sync (".",
                       cmd,
                       NULL,                  /* Environment. */
                       G_SPAWN_SEARCH_PATH,
                       NULL,                  /* Setup function. */
                       NULL,
                       &standard_out,
                       &standard_err,
                       &exit_status,
                       NULL)
         == FALSE)
        || (WIFEXITED (exit_status) == 0)
        || WEXITSTATUS (exit_status))
      {
        g_warning ("%s: failed rename: %d (WIF %i, WEX %i)",
                   __FUNCTION__,
                   exit_status,
                   WIFEXITED (exit_status),
                 WEXITSTATUS (exit_status));
        g_debug ("%s: stdout: %s\n", __FUNCTION__, standard_out);
        g_debug ("%s: stderr: %s\n", __FUNCTION__, standard_err);
        g_free (old_dir);
        g_free (new_dir);
        g_free (cmd[0]);
        g_free (cmd);
        sql ("ROLLBACK;");
        return -1;
      }

    g_free (cmd[0]);
    g_free (cmd);
  }

  g_free (old_dir);
  g_free (new_dir);

  /* Set the database version to 38. */

  set_db_version (38);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 38 to version 39.
 *
 * @return 0 success, -1 error.
 */
int
migrate_38_to_39 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 38. */

  if (manage_db_version () != 38)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The w3af NVT (80109) was removed from the predefined configs. */

  /* Just update the config comments, because init_manage will add the new
   * selectors. */

  sql ("UPDATE configs SET comment ="
       " 'Most NVT''s; optimized by using previously collected information.'"
       " WHERE id = " G_STRINGIFY (CONFIG_ID_FULL_AND_FAST) ";");

  sql ("UPDATE configs SET comment ="
       " 'Most NVT''s including those that can stop services/hosts;"
       " optimized by using previously collected information.'"
       " WHERE id = " G_STRINGIFY (CONFIG_ID_FULL_AND_FAST_ULTIMATE) ";");

  sql ("UPDATE configs SET comment ="
       " 'Most NVT''s; don''t trust previously collected information; slow.'"
       " WHERE id = " G_STRINGIFY (CONFIG_ID_FULL_AND_VERY_DEEP) ";");

  sql ("UPDATE configs SET comment ="
       " 'Most NVT''s including those that can stop services/hosts;"
       " don''t trust previously collected information; slow.'"
       " WHERE id = " G_STRINGIFY (CONFIG_ID_FULL_AND_VERY_DEEP_ULTIMATE) ";");

  /* Set the database version to 39. */

  set_db_version (39);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Set the pref for migrate_39_to_40.
 *
 * @param[in]  config  Config to set pref on.
 */
void
migrate_39_to_40_set_pref (config_t config)
{
  sql ("UPDATE config_preferences SET value = 'yes'"
       " WHERE config = %llu"
       " AND type = 'SERVER_PREFS'"
       " AND name = 'unscanned_closed';",
       config);
}

/**
 * @brief Migrate the database from version 39 to version 40.
 *
 * @return 0 success, -1 error.
 */
int
migrate_39_to_40 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 39. */

  if (manage_db_version () != 39)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The preference "unscanned_closed" was set to yes in the predefined
   * configs. */

  /** @todo ROLLBACK on failure. */

  migrate_39_to_40_set_pref (CONFIG_ID_FULL_AND_FAST);
  migrate_39_to_40_set_pref (CONFIG_ID_FULL_AND_FAST_ULTIMATE);
  migrate_39_to_40_set_pref (CONFIG_ID_FULL_AND_VERY_DEEP);
  migrate_39_to_40_set_pref (CONFIG_ID_FULL_AND_VERY_DEEP_ULTIMATE);

  /* Set the database version to 40. */

  set_db_version (40);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 40 to version 41.
 *
 * @return 0 success, -1 error.
 */
int
migrate_40_to_41 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 40. */

  if (manage_db_version () != 40)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* For report formats, feed signatures were given priority over signatures
   * in imported XML.  This includes only setting the db signature when it is
   * imported.  So remove the db signatures for all predefined reports. */

  /** @todo ROLLBACK on failure. */

  sql ("UPDATE report_formats SET signature = NULL"
       " WHERE uuid = 'a0704abb-2120-489f-959f-251c9f4ffebd';");
  sql ("UPDATE report_formats SET signature = NULL"
       " WHERE uuid = 'b993b6f5-f9fb-4e6e-9c94-dd46c00e058d';");
  sql ("UPDATE report_formats SET signature = NULL"
       " WHERE uuid = '929884c6-c2c4-41e7-befb-2f6aa163b458';");
  sql ("UPDATE report_formats SET signature = NULL"
       " WHERE uuid = '9f1ab17b-aaaa-411a-8c57-12df446f5588';");
  sql ("UPDATE report_formats SET signature = NULL"
       " WHERE uuid = 'f5c2a364-47d2-4700-b21d-0a7693daddab';");
  sql ("UPDATE report_formats SET signature = NULL"
       " WHERE uuid = '1a60a67e-97d0-4cbf-bc77-f71b08e7043d';");
  sql ("UPDATE report_formats SET signature = NULL"
       " WHERE uuid = '19f6f1b3-7128-4433-888c-ccc764fe6ed5';");
  sql ("UPDATE report_formats SET signature = NULL"
       " WHERE uuid = 'd5da9f67-8551-4e51-807b-b6a873d70e34';");

  /* Set the database version to 41. */

  set_db_version (41);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 41 to version 42.
 *
 * @return 0 success, -1 error.
 */
int
migrate_41_to_42 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Require that the database is currently version 41. */

  if (manage_db_version () != 41)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Two task tables got trashcan location fields. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE tasks ADD column config_location INTEGER;");
  sql ("ALTER TABLE tasks ADD column target_location INTEGER;");
  sql ("ALTER TABLE tasks ADD column schedule_location INTEGER;");
  sql ("ALTER TABLE tasks ADD column slave_location INTEGER;");

  sql ("UPDATE tasks SET"
       " config_location = " G_STRINGIFY (LOCATION_TABLE) ","
       " target_location = " G_STRINGIFY (LOCATION_TABLE) ","
       " schedule_location = " G_STRINGIFY (LOCATION_TABLE) ","
       " slave_location = " G_STRINGIFY (LOCATION_TABLE) ";");

  /* Ensure that the task_escalators table exists. */
  sql ("CREATE TABLE IF NOT EXISTS task_escalators"
       " (id INTEGER PRIMARY KEY, task INTEGER, escalator INTEGER);");

  sql ("ALTER TABLE task_escalators ADD column escalator_location INTEGER;");

  sql ("UPDATE task_escalators"
       " SET escalator_location = " G_STRINGIFY (LOCATION_TABLE) ";");

  /* Set the database version to 42. */

  set_db_version (42);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 42 to version 43.
 *
 * @return 0 success, -1 error.
 */
int
migrate_42_to_43 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Require that the database is currently version 42. */

  if (manage_db_version () != 42)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The targets table got an ssh_port field. */

  /** @todo ROLLBACK on failure. */

  /* Ensure that the targets_trash table exists. */
  sql ("CREATE TABLE IF NOT EXISTS targets_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, hosts,"
       "  comment, lsc_credential INTEGER, smb_lsc_credential INTEGER,"
       "  port_range, ssh_location INTEGER, smb_location INTEGER);");

  sql ("ALTER TABLE targets ADD column ssh_port;");
  sql ("ALTER TABLE targets_trash ADD column ssh_port;");

  sql ("UPDATE targets SET ssh_port = 22"
       " WHERE lsc_credential > 0;");
  sql ("UPDATE targets_trash SET ssh_port = 22"
       " WHERE lsc_credential > 0;");

  /* Set the database version to 43. */

  set_db_version (43);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 43 to version 44.
 *
 * @return 0 success, -1 error.
 */
int
migrate_43_to_44 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Require that the database is currently version 43. */

  if (manage_db_version () != 43)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The file permission got much tighter. */

  if (chmod (task_db_name ? task_db_name : OPENVAS_STATE_DIR "/mgr/tasks.db",
             S_IRUSR | S_IWUSR))
    {
      g_warning ("%s: failed to chmod %s: %s",
                 __FUNCTION__,
                 task_db_name ? task_db_name
                              : OPENVAS_STATE_DIR "/mgr/tasks.db",
                 strerror (errno));
      sql ("ROLLBACK;");
      return -1;
    }

  /* Set the database version to 44. */

  set_db_version (44);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 44 to version 45.
 *
 * @return 0 success, -1 error.
 */
int
migrate_44_to_45 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Require that the database is currently version 44. */

  if (manage_db_version () != 44)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The tasks table got a upload_result_count column. */

  sql ("ALTER TABLE tasks ADD column upload_result_count;");
  sql ("UPDATE tasks SET upload_result_count = -1;");

  /* Set the database version to 45. */

  set_db_version (45);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 45 to version 46.
 *
 * @return 0 success, -1 error.
 */
int
migrate_45_to_46 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Require that the database is currently version 45. */

  if (manage_db_version () != 45)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* CREATE_TARGET now cleans the hosts string. */

  sql ("UPDATE targets SET hosts = clean_hosts (hosts);");
  sql ("UPDATE targets_trash SET hosts = clean_hosts (hosts);");

  /* Set the database version to 46. */

  set_db_version (46);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 46 to version 47.
 *
 * @return 0 success, -1 error.
 */
int
migrate_46_to_47 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Require that the database is currently version 46. */

  if (manage_db_version () != 46)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Performance prefs move from config to task. */

  /* Ensure that the table exists. */
  sql ("CREATE TABLE IF NOT EXISTS task_preferences"
       " (id INTEGER PRIMARY KEY, task INTEGER, name, value);");

  sql ("INSERT INTO task_preferences (task, name, value)"
       " SELECT tasks.ROWID, config_preferences.name, config_preferences.value"
       " FROM tasks, config_preferences"
       " WHERE tasks.config = config_preferences.config"
       " AND (config_preferences.name = 'max_checks'"
       "      OR config_preferences.name = 'max_hosts')");

  /* Set the database version to 47. */

  set_db_version (47);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 47 to version 48.
 *
 * @return 0 success, -1 error.
 */
int
migrate_47_to_48 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Require that the database is currently version 47. */

  if (manage_db_version () != 47)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Scanner "app" host detail changed name to "App". */

  /* Ensure that the table exists. */
  sql ("CREATE TABLE IF NOT EXISTS report_host_details"
       " (id INTEGER PRIMARY KEY, report_host INTEGER, source_type,"
       "  source_name, source_description, name, value);");

  sql ("UPDATE report_host_details SET name = 'App' WHERE name = 'app';");

  /* Set the database version to 48. */

  set_db_version (48);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 48 to version 49.
 *
 * @return 0 success, -1 error.
 */
int
migrate_48_to_49 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Require that the database is currently version 48. */

  if (manage_db_version () != 48)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* If the example task was created before version 14 then the 13 to 14
   * migrator would have given the example result an arbitrary UUID instead
   * of the predefined one.
   *
   * Also, the host of the example result has now changed to an IP. */

  sql ("UPDATE results SET uuid = 'cb291ec0-1b0d-11df-8aa1-002264764cea'"
       " WHERE host = 'localhost';");

  sql ("UPDATE results SET host = '127.0.0.1'"
       " WHERE uuid = 'cb291ec0-1b0d-11df-8aa1-002264764cea';");

  sql ("UPDATE report_hosts SET host = '127.0.0.1'"
       " WHERE host = 'localhost';");

  /* Set the database version to 49. */

  set_db_version (49);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 49 to version 50.
 *
 * @return 0 success, -1 error.
 */
int
migrate_49_to_50 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 49. */

  if (manage_db_version () != 49)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The UNIQUE constraint in task_preferences was removed. */

  /* Move the table away. */

  sql ("ALTER TABLE task_preferences RENAME TO task_preferences_49;");

  /* Create the table in the new format. */

  sql ("CREATE TABLE IF NOT EXISTS task_preferences"
       " (id INTEGER PRIMARY KEY, task INTEGER, name, value);");

  /* Copy the data into the new table. */

  sql ("INSERT into task_preferences"
       " (id, task, name, value)"
       " SELECT"
       "  id, task, name, value"
       " FROM task_preferences_49;");

  /* Drop the old tables. */

  sql ("DROP TABLE task_preferences_49;");

  /* Set the database version to 50. */

  set_db_version (50);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 50 to version 51.
 *
 * @return 0 success, -1 error.
 */
int
migrate_50_to_51 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 50. */

  if (manage_db_version () != 50)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The user table got a timezone column. */

  sql ("ALTER TABLE users ADD column timezone;");
  sql ("UPDATE users SET timezone = NULL;");

  /* Set the database version to 51. */

  set_db_version (51);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Convert a UTC text time to an integer time since the Epoch.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
migrate_51_to_52_sql_convert (sqlite3_context *context, int argc,
                              sqlite3_value** argv)
{
  const unsigned char *text_time;
  int epoch_time;
  struct tm tm;

  assert (argc == 1);

  text_time = sqlite3_value_text (argv[0]);
  if (text_time)
    {
      /* Scanner uses ctime: "Wed Jun 30 21:49:08 1993".
       *
       * The dates being converted are in the timezone that the Scanner was using.
       *
       * As a special case for this migrator, openvasmd.c uses the timezone
       * from the environment, instead of forcing UTC.  This allows the user
       * to set the timezone to be the same as the Scanner timezone, so
       * that these dates are converted from the Scanner timezone.  Even if
       * the user just leaves the timezone as is, it is likely to be the same
       * timezone she/he is running the Scanner under.
       */
      if (text_time && (strlen ((char*) text_time) > 0))
        {
          if (strptime ((char*) text_time, "%a %b %d %H:%M:%S %Y", &tm) == NULL)
            {
              sqlite3_result_error (context, "Failed to parse time", -1);
              return;
            }
          epoch_time = mktime (&tm);
          if (epoch_time == -1)
            {
              sqlite3_result_error (context, "Failed to make time", -1);
              return;
            }
        }
      else
        epoch_time = 0;
    }
  else
    epoch_time = 0;
  sqlite3_result_int (context, epoch_time);
}

/**
 * @brief Migrate the database from version 51 to version 52.
 *
 * @return 0 success, -1 error.
 */
int
migrate_51_to_52 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 51. */

  if (manage_db_version () != 51)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Add an SQL helper. */

  if (sqlite3_create_function (task_db,
                               "convert",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               migrate_51_to_52_sql_convert,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create convert", __FUNCTION__);
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Date storage switched from text format to seconds since the epoch. */

  sql ("UPDATE report_hosts SET start_time = convert (start_time);");
  sql ("UPDATE report_hosts SET end_time = convert (end_time);");
  sql ("UPDATE reports SET start_time = convert (start_time);");
  sql ("UPDATE reports SET end_time = convert (end_time);");
  sql ("UPDATE tasks SET start_time = convert (start_time);");
  sql ("UPDATE tasks SET end_time = convert (end_time);");

  /* Set the database version to 52. */

  set_db_version (52);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 52 to version 53.
 *
 * @return 0 success, -1 error.
 */
int
migrate_52_to_53 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 52. */

  if (manage_db_version () != 52)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The overrides table got a end_time column. */

  /* Ensure that the table exists. */
  sql ("CREATE TABLE IF NOT EXISTS overrides"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt,"
       "  creation_time, modification_time, text, hosts, port, threat,"
       "  new_threat, task INTEGER, result INTEGER);");

  sql ("ALTER TABLE overrides ADD column end_time;");
  sql ("UPDATE overrides SET end_time = 0;");

  /* Set the database version to 53. */

  set_db_version (53);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 53 to version 54.
 *
 * @return 0 success, -1 error.
 */
int
migrate_53_to_54 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 53. */

  if (manage_db_version () != 53)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The notes table got a end_time column. */

  /* Ensure that the table exists. */
  sql ("CREATE TABLE IF NOT EXISTS notes"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt,"
       "  creation_time, modification_time, text, hosts, port, threat,"
       "  task INTEGER, result INTEGER);");

  sql ("ALTER TABLE notes ADD column end_time;");
  sql ("UPDATE notes SET end_time = 0;");

  /* Set the database version to 54. */

  set_db_version (54);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate a report format from version 54 to version 55.
 *
 * @param[in]  old_uuid  Old UUID.
 * @param[in]  new_uuid  New UUID.
 *
 * @return 0 success, -1 error.
 */
int
migrate_54_to_55_format (const char *old_uuid, const char *new_uuid)
{
  gchar *dir;

  dir = g_build_filename (OPENVAS_DATA_DIR,
                          "openvasmd",
                          "global_report_formats",
                          old_uuid,
                          NULL);

  if (g_file_test (dir, G_FILE_TEST_EXISTS) && openvas_file_remove_recurse (dir))
    {
      g_warning ("%s: failed to remove dir %s", __FUNCTION__, dir);
      g_free (dir);
      return -1;
    }
  g_free (dir);

  sql ("UPDATE report_formats"
       " SET uuid = '%s'"
       " WHERE uuid = '%s';",
       new_uuid,
       old_uuid);

  return 0;
}

/**
 * @brief Migrate the database from version 54 to version 55.
 *
 * @return 0 success, -1 error.
 */
int
migrate_54_to_55 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 54. */

  if (manage_db_version () != 54)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* For report formats, feed signatures were given priority over signatures
   * in imported XML.  This includes only setting the db signature when it is
   * imported.  So remove the db signatures for all predefined reports. */

  /** @todo ROLLBACK on failure. */

  if (migrate_54_to_55_format ("a0704abb-2120-489f-959f-251c9f4ffebd",
                               "5ceff8ba-1f62-11e1-ab9f-406186ea4fc5"))
    {
      sql ("ROLLBACK;");
      return -1;
    }

  if (migrate_54_to_55_format ("b993b6f5-f9fb-4e6e-9c94-dd46c00e058d",
                               "6c248850-1f62-11e1-b082-406186ea4fc5"))
    {
      sql ("ROLLBACK;");
      return -1;
    }

  if (migrate_54_to_55_format ("929884c6-c2c4-41e7-befb-2f6aa163b458",
                               "77bd6c4a-1f62-11e1-abf0-406186ea4fc5"))
    {
      sql ("ROLLBACK;");
      return -1;
    }

  if (migrate_54_to_55_format ("9f1ab17b-aaaa-411a-8c57-12df446f5588",
                               "7fcc3a1a-1f62-11e1-86bf-406186ea4fc5"))
    {
      sql ("ROLLBACK;");
      return -1;
    }

  if (migrate_54_to_55_format ("f5c2a364-47d2-4700-b21d-0a7693daddab",
                               "9ca6fe72-1f62-11e1-9e7c-406186ea4fc5"))
    {
      sql ("ROLLBACK;");
      return -1;
    }

  if (migrate_54_to_55_format ("1a60a67e-97d0-4cbf-bc77-f71b08e7043d",
                               "a0b5bfb2-1f62-11e1-85db-406186ea4fc5"))
    {
      sql ("ROLLBACK;");
      return -1;
    }

  if (migrate_54_to_55_format ("19f6f1b3-7128-4433-888c-ccc764fe6ed5",
                               "a3810a62-1f62-11e1-9219-406186ea4fc5"))
    {
      sql ("ROLLBACK;");
      return -1;
    }

  if (migrate_54_to_55_format ("d5da9f67-8551-4e51-807b-b6a873d70e34",
                               "a994b278-1f62-11e1-96ac-406186ea4fc5"))
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Set the database version to 55. */

  set_db_version (55);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Insert a port range.
 */
#define MIGRATE_55_TO_56_RANGE(type, start, end)                         \
  sql ("INSERT INTO port_ranges"                                 \
       " (uuid, port_list, type, start, end, comment, exclude)"  \
       " VALUES"                                                 \
       " (make_uuid (), %llu, %i,"                               \
       "  '" G_STRINGIFY (start) "',"                            \
       "  '" G_STRINGIFY (end) "',"                              \
       "  '', 0)",                                               \
       list,                                                     \
       type)

/**
 * @brief Ensure that the predefined port lists exist.
 */
void
migrate_55_to_56_ensure_predefined_port_lists_exist ()
{
  if (sql_int (0, 0,
               "SELECT count(*) FROM port_lists"
               " WHERE uuid = '" PORT_LIST_UUID_DEFAULT "';")
      == 0)
    {
      resource_t list;
      sql ("INSERT INTO port_lists (uuid, owner, name, comment)"
           " VALUES ('" PORT_LIST_UUID_DEFAULT "', NULL, 'OpenVAS Default',"
           " '')");
      list = sqlite3_last_insert_rowid (task_db);

      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1, 5);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7, 7);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9, 9);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 11, 11);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 13, 13);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 15, 15);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 17, 25);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 27, 27);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 29, 29);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 31, 31);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 33, 33);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 35, 35);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 37, 39);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 41, 59);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 61, 224);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 242, 248);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 256, 268);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 280, 287);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 308, 322);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 333, 333);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 344, 700);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 702, 702);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 704, 707);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 709, 711);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 721, 721);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 723, 723);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 729, 731);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 740, 742);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 744, 744);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 747, 754);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 758, 765);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 767, 767);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 769, 777);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 780, 783);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 786, 787);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 799, 801);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 808, 808);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 810, 810);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 828, 829);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 847, 848);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 860, 860);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 871, 871);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 873, 873);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 886, 888);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 898, 898);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 900, 904);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 911, 913);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 927, 927);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 950, 950);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 953, 953);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 975, 975);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 989, 1002);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1005, 1005);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1008, 1008);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1010, 1010);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1023, 1027);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1029, 1036);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1040, 1040);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1042, 1042);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1045, 1045);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1047, 1112);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1114, 1117);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1119, 1120);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1122, 1127);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1139, 1139);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1154, 1155);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1161, 1162);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1168, 1170);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1178, 1178);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1180, 1181);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1183, 1188);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1194, 1194);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1199, 1231);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1233, 1286);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1288, 1774);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 1776, 2028);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2030, 2030);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2032, 2035);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2037, 2038);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2040, 2065);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2067, 2083);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2086, 2087);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2089, 2152);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2155, 2155);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2159, 2167);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2170, 2177);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2180, 2181);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2190, 2191);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2199, 2202);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2213, 2213);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2220, 2223);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2232, 2246);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2248, 2255);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2260, 2260);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2273, 2273);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2279, 2289);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2294, 2311);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2313, 2371);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2381, 2425);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2427, 2681);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2683, 2824);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2826, 2854);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2856, 2924);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 2926, 3096);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3098, 3299);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3302, 3321);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3326, 3366);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3372, 3403);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3405, 3545);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3547, 3707);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3709, 3765);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3767, 3770);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3772, 3800);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3802, 3802);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3845, 3871);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3875, 3876);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3885, 3885);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3900, 3900);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3928, 3929);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3939, 3939);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3959, 3959);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3970, 3971);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3984, 3987);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 3999, 4036);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4040, 4042);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4045, 4045);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4080, 4080);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4096, 4100);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4111, 4111);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4114, 4114);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4132, 4134);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4138, 4138);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4141, 4145);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4154, 4154);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4160, 4160);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4199, 4200);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4242, 4242);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4300, 4300);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4321, 4321);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4333, 4333);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4343, 4351);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4353, 4358);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4369, 4369);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4400, 4400);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4442, 4457);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4480, 4480);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4500, 4500);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4545, 4547);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4555, 4555);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4557, 4557);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4559, 4559);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4567, 4568);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4600, 4601);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4658, 4662);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4672, 4672);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4752, 4752);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4800, 4802);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4827, 4827);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4837, 4839);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4848, 4849);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4868, 4869);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4885, 4885);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4894, 4894);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4899, 4899);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4950, 4950);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4983, 4983);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4987, 4989);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 4998, 4998);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5000, 5011);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5020, 5025);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5031, 5031);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5042, 5042);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5050, 5057);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5060, 5061);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5064, 5066);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5069, 5069);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5071, 5071);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5081, 5081);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5093, 5093);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5099, 5102);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5137, 5137);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5145, 5145);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5150, 5152);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5154, 5154);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5165, 5165);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5190, 5193);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5200, 5203);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5222, 5222);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5225, 5226);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5232, 5232);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5236, 5236);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5250, 5251);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5264, 5265);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5269, 5269);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5272, 5272);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5282, 5282);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5300, 5311);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5314, 5315);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5351, 5355);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5400, 5432);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5435, 5435);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5454, 5456);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5461, 5463);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5465, 5465);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5500, 5504);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5510, 5510);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5520, 5521);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5530, 5530);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5540, 5540);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5550, 5550);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5553, 5556);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5566, 5566);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5569, 5569);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5595, 5605);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5631, 5632);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5666, 5666);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5673, 5680);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5688, 5688);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5690, 5690);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5713, 5717);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5720, 5720);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5729, 5730);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5741, 5742);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5745, 5746);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5755, 5755);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5757, 5757);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5766, 5768);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5771, 5771);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5800, 5803);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5813, 5813);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5858, 5859);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5882, 5882);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5888, 5889);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5900, 5903);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5968, 5969);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5977, 5979);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5987, 5991);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 5997, 6010);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6050, 6051);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6064, 6073);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6085, 6085);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6100, 6112);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6123, 6123);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6141, 6150);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6175, 6177);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6200, 6200);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6253, 6253);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6255, 6255);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6270, 6270);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6300, 6300);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6321, 6322);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6343, 6343);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6346, 6347);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6373, 6373);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6382, 6382);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6389, 6389);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6400, 6400);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6455, 6456);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6471, 6471);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6500, 6503);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6505, 6510);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6543, 6543);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6547, 6550);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6558, 6558);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6566, 6566);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6580, 6582);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6588, 6588);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6620, 6621);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6623, 6623);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6628, 6628);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6631, 6631);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6665, 6670);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6672, 6673);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6699, 6701);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6714, 6714);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6767, 6768);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6776, 6776);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6788, 6790);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6831, 6831);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6841, 6842);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6850, 6850);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6881, 6889);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6891, 6891);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6901, 6901);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6939, 6939);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6961, 6966);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6969, 6970);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 6998, 7015);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7020, 7021);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7030, 7030);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7070, 7070);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7099, 7100);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7121, 7121);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7161, 7161);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7170, 7170);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7174, 7174);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7200, 7201);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7210, 7210);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7269, 7269);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7273, 7273);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7280, 7281);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7283, 7283);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7300, 7300);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7320, 7320);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7326, 7326);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7391, 7392);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7395, 7395);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7426, 7431);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7437, 7437);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7464, 7464);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7491, 7491);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7501, 7501);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7510, 7511);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7544, 7545);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7560, 7560);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7566, 7566);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7570, 7570);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7575, 7575);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7588, 7588);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7597, 7597);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7624, 7624);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7626, 7627);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7633, 7634);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7648, 7649);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7666, 7666);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7674, 7676);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7743, 7743);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7775, 7779);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7781, 7781);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7786, 7786);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7797, 7798);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7800, 7801);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7845, 7846);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7875, 7875);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7902, 7902);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7913, 7913);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7932, 7933);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7967, 7967);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7979, 7980);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 7999, 8005);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8007, 8010);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8022, 8022);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8032, 8033);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8044, 8044);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8074, 8074);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8080, 8082);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8088, 8089);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8098, 8098);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8100, 8100);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8115, 8116);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8118, 8118);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8121, 8122);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8130, 8132);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8160, 8161);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8181, 8194);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8199, 8201);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8204, 8208);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8224, 8225);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8245, 8245);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8311, 8311);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8351, 8351);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8376, 8380);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8400, 8403);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8416, 8417);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8431, 8431);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8443, 8444);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8450, 8450);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8473, 8473);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8554, 8555);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8649, 8649);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8733, 8733);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8763, 8765);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8786, 8787);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8804, 8804);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8863, 8864);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8875, 8875);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8880, 8880);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8888, 8894);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8900, 8901);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8910, 8911);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8954, 8954);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8989, 8989);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 8999, 9002);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9006, 9006);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9009, 9009);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9020, 9026);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9080, 9080);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9090, 9091);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9100, 9103);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9110, 9111);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9131, 9131);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9152, 9152);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9160, 9164);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9200, 9207);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9210, 9211);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9217, 9217);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9281, 9285);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9287, 9287);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9292, 9292);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9321, 9321);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9343, 9344);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9346, 9346);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9374, 9374);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9390, 9390);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9396, 9397);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9400, 9400);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9418, 9418);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9495, 9495);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9500, 9500);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9535, 9537);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9593, 9595);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9600, 9600);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9612, 9612);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9704, 9704);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9747, 9747);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9753, 9753);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9797, 9797);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9800, 9802);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9872, 9872);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9875, 9876);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9888, 9889);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9898, 9901);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9909, 9909);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9911, 9911);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9950, 9952);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 9990, 10005);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 10007, 10008);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 10012, 10012);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 10080, 10083);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 10101, 10103);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 10113, 10116);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 10128, 10128);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 10252, 10252);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 10260, 10260);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 10288, 10288);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 10607, 10607);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 10666, 10666);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 10752, 10752);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 10990, 10990);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 11000, 11001);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 11111, 11111);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 11201, 11201);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 11223, 11223);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 11319, 11321);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 11367, 11367);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 11371, 11371);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 11600, 11600);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 11720, 11720);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 11751, 11751);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 11965, 11965);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 11967, 11967);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 11999, 12006);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 12076, 12076);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 12109, 12109);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 12168, 12168);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 12172, 12172);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 12223, 12223);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 12321, 12321);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 12345, 12346);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 12361, 12362);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 12468, 12468);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 12701, 12701);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 12753, 12753);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 13160, 13160);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 13223, 13224);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 13701, 13702);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 13705, 13706);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 13708, 13718);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 13720, 13722);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 13724, 13724);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 13782, 13783);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 13818, 13822);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 14001, 14001);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 14033, 14034);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 14141, 14141);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 14145, 14145);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 14149, 14149);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 14194, 14194);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 14237, 14237);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 14936, 14937);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 15000, 15000);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 15126, 15126);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 15345, 15345);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 15363, 15363);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 16360, 16361);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 16367, 16368);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 16384, 16384);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 16660, 16661);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 16959, 16959);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 16969, 16969);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 16991, 16991);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 17007, 17007);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 17185, 17185);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 17219, 17219);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 17300, 17300);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 17770, 17772);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 18000, 18000);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 18181, 18187);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 18190, 18190);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 18241, 18241);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 18463, 18463);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 18769, 18769);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 18888, 18888);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 19191, 19191);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 19194, 19194);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 19283, 19283);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 19315, 19315);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 19398, 19398);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 19410, 19412);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 19540, 19541);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 19638, 19638);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 19726, 19726);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 20000, 20001);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 20005, 20005);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 20011, 20012);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 20034, 20034);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 20200, 20200);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 20202, 20203);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 20222, 20222);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 20670, 20670);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 20999, 21000);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 21490, 21490);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 21544, 21544);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 21590, 21590);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 21800, 21800);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 21845, 21849);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 22000, 22001);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 22222, 22222);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 22273, 22273);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 22289, 22289);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 22305, 22305);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 22321, 22321);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 22370, 22370);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 22555, 22555);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 22800, 22800);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 22951, 22951);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 23456, 23456);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 24000, 24006);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 24242, 24242);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 24249, 24249);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 24345, 24347);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 24386, 24386);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 24554, 24554);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 24677, 24678);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 24922, 24922);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 25000, 25009);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 25378, 25378);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 25544, 25544);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 25793, 25793);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 25867, 25867);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 25901, 25901);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 25903, 25903);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 26000, 26000);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 26208, 26208);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 26260, 26264);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 27000, 27010);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 27345, 27345);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 27374, 27374);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 27504, 27504);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 27665, 27665);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 27999, 27999);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 28001, 28001);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 29559, 29559);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 29891, 29891);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 30001, 30002);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 30100, 30102);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 30303, 30303);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 30999, 30999);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 31337, 31337);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 31339, 31339);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 31416, 31416);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 31457, 31457);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 31554, 31554);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 31556, 31556);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 31620, 31620);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 31765, 31765);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 31785, 31787);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 32261, 32261);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 32666, 32666);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 32768, 32780);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 32786, 32787);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 32896, 32896);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 33270, 33270);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 33331, 33331);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 33434, 33434);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 33911, 33911);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 34249, 34249);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 34324, 34324);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 34952, 34952);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 36865, 36865);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 37475, 37475);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 37651, 37651);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 38037, 38037);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 38201, 38201);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 38292, 38293);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 39681, 39681);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 40412, 40412);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 40841, 40843);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 41111, 41111);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 41508, 41508);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 41794, 41795);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 42508, 42510);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 43118, 43118);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 43188, 43190);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 44321, 44322);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 44333, 44334);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 44442, 44443);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 44818, 44818);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 45000, 45000);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 45054, 45054);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 45678, 45678);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 45966, 45966);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 47000, 47000);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 47557, 47557);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 47624, 47624);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 47806, 47806);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 47808, 47808);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 47891, 47891);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 48000, 48003);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 48556, 48556);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 49400, 49400);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 50000, 50004);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 50505, 50505);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 50776, 50776);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 51210, 51210);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 53001, 53001);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 54320, 54321);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 57341, 57341);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 59595, 59595);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 60177, 60177);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 60179, 60179);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 61439, 61441);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 61446, 61446);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 65000, 65000);
      MIGRATE_55_TO_56_RANGE (PORT_PROTOCOL_TCP, 65301, 65301);
    }
}

/**
 * @brief Migrate the database from version 55 to version 56.
 *
 * @return 0 success, -1 error.
 */
int
migrate_55_to_56 ()
{
  iterator_t rows;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 55. */

  if (manage_db_version () != 55)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The port_range in the targets and targets_trash tables changed to
   * refer to a port list.  The targets_trash table got a port_list_location
   * column. */

  /** @todo ROLLBACK on failure. */

  /* Add the new column. */

  sql ("ALTER TABLE targets_trash ADD COLUMN port_list_location;");
  sql ("UPDATE targets_trash"
       " SET port_list_location = " G_STRINGIFY (LOCATION_TRASH) ";");

  /* Ensure the new tables exist for the migrator. */

  sql ("CREATE TABLE IF NOT EXISTS port_lists"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment);");
  sql ("CREATE TABLE IF NOT EXISTS port_lists_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment);");
  sql ("CREATE TABLE IF NOT EXISTS port_ranges"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, port_list INTEGER, type,"
       "  start, end, comment, exclude);");
  sql ("CREATE TABLE IF NOT EXISTS port_ranges_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, port_list INTEGER, type,"
       "  start, end, comment, exclude);");

  migrate_55_to_56_ensure_predefined_port_lists_exist ();

  /* Make a port list and port range(s) for each target. */

  init_iterator (&rows, "SELECT ROWID, owner, name, port_range FROM targets;");
  while (next (&rows))
    {
      resource_t target;
      const gchar *range;

      target = iterator_int64 (&rows, 0);
      range = iterator_string (&rows, 3);

      if (range && strcmp (range, "default"))
        {
          resource_t owner, list;
          const gchar *name;
          gchar *quoted_name;

          owner = iterator_int64 (&rows, 1);
          name = iterator_string (&rows, 2);
          quoted_name = sql_quote (name);

          /* Make the port list.  Store target in comment for modification
           * outside iteration. */

          sql ("INSERT INTO port_lists (uuid, owner, name, comment)"
               " VALUES (make_uuid (), %llu, '%s', %llu)",
               owner,
               quoted_name,
               target);

          g_free (quoted_name);

          list = sqlite3_last_insert_rowid (task_db);

          /* Convert old range (1-100,1649,210-214) to multiple new ranges. */

          {
            gchar **split, **point;

            while (*range && isblank (*range)) range++;

            split = g_strsplit (range, ",", 0);
            point = split;

            while (*point)
              {
                gchar *hyphen;

                hyphen = strchr (*point, '-');
                if (hyphen)
                  {
                    *hyphen = '\0';
                    hyphen++;

                    /* A range. */

                    sql ("INSERT INTO port_ranges"
                         " (uuid, port_list, type, start, end, comment,"
                         "  exclude)"
                         " VALUES"
                         " (make_uuid (), %llu, %i, %s, %s, '', 0)",
                         list,
                         PORT_PROTOCOL_TCP,
                         *point,
                         hyphen);
                  }
                else
                  {
                    /* A single port. */

                    sql ("INSERT INTO port_ranges"
                         " (uuid, port_list, type, start, end, comment,"
                         "  exclude)"
                         " VALUES"
                         " (make_uuid (), %llu, %i, %s, NULL, '',"
                         " 0)",
                         list,
                         PORT_PROTOCOL_TCP,
                         *point);
                  }
                point += 1;
              }

            g_strfreev (split);
          }
        }
      else
        sql ("UPDATE targets SET port_range"
             " = (SELECT ROWID FROM port_lists"
             "    WHERE uuid = '" PORT_LIST_UUID_DEFAULT "')"
             " WHERE ROWID = %llu;",
             target);
    }
  cleanup_iterator (&rows);

  /* Set the port_ranges of the targets to the new port lists. */

  sql ("UPDATE targets SET"
       " port_range = (SELECT ROWID FROM port_lists"
       "               WHERE comment = targets.ROWID)"
       " WHERE port_range"
       " != (SELECT ROWID FROM port_lists"
       "     WHERE uuid = '" PORT_LIST_UUID_DEFAULT "');");

  sql ("UPDATE port_lists SET"
       " comment = 'Migrated from target '"
       "           || (SELECT targets.name FROM targets"
       "               WHERE port_lists.ROWID = targets.port_range)"
       "           || '.'"
       " WHERE uuid != '" PORT_LIST_UUID_DEFAULT "';");

  /* Make a port list and port range(s) for each trash target. */

  init_iterator (&rows,
                 "SELECT ROWID, owner, name, port_range FROM targets_trash;");
  while (next (&rows))
    {
      resource_t target;
      gchar *range;

      target = iterator_int64 (&rows, 0);
      range = g_strdup (iterator_string (&rows, 3));

      if (range && strcmp (range, "default"))
        {
          resource_t owner, list;
          const gchar *name;
          gchar *quoted_name;

          owner = iterator_int64 (&rows, 1);
          name = iterator_string (&rows, 2);
          quoted_name = sql_quote (name);

          /* Make the port list.  Store target in comment for modification
           * outside iteration. */

          sql ("INSERT INTO port_lists_trash (uuid, owner, name, comment)"
               " VALUES (make_uuid (), %llu, '%s', %llu)",
               owner,
               quoted_name,
               target);

          g_free (quoted_name);

          list = sqlite3_last_insert_rowid (task_db);

          /* Convert old range (1-100,1649,210-214) to multiple new ranges. */

          {
            gchar **split, **point;

            while (*range && isblank (*range)) range++;

            split = g_strsplit (range, ",", 0);
            point = split;

            while (*point)
              {
                gchar *hyphen;

                hyphen = strchr (*point, '-');
                if (hyphen)
                  {
                    *hyphen = '\0';
                    hyphen++;

                    /* A range. */

                    sql ("INSERT INTO port_ranges_trash"
                         " (uuid, port_list, type, start, end, comment,"
                         "  exclude)"
                         " VALUES"
                         " (make_uuid (), %llu, %i, %s, %s, '', 0)",
                         list,
                         PORT_PROTOCOL_TCP,
                         *point,
                         hyphen);
                  }
                else
                  {
                    /* A single port. */

                    sql ("INSERT INTO port_ranges_trash"
                         " (uuid, port_list, type, start, end, comment,"
                         "  exclude)"
                         " VALUES"
                         " (make_uuid (), %llu, %i, %s, NULL, '',"
                         " 0)",
                         list,
                         PORT_PROTOCOL_TCP,
                         *point);
                  }
                point += 1;
              }

            g_strfreev (split);
          }
        }
      else
        sql ("UPDATE targets_trash SET port_range"
             " = (SELECT ROWID FROM port_lists"
             "    WHERE uuid = '" PORT_LIST_UUID_DEFAULT "'),"
             " port_list_location = " G_STRINGIFY (LOCATION_TABLE)
             " WHERE ROWID = %llu;",
             target);

      g_free (range);
    }
  cleanup_iterator (&rows);

  /* Set the port_ranges of the trash targets to the new port lists. */

  sql ("UPDATE targets_trash SET"
       " port_range = (SELECT ROWID FROM port_lists_trash"
       "               WHERE comment = targets_trash.ROWID)"
       " WHERE port_range"
       " != (SELECT ROWID FROM port_lists"
       "     WHERE uuid = '" PORT_LIST_UUID_DEFAULT "');");

  sql ("UPDATE port_lists_trash SET"
       " comment = 'Migrated from trashcan target '"
       "           || (SELECT targets_trash.name FROM targets_trash"
       "               WHERE port_lists_trash.ROWID = targets_trash.port_range)"
       "           || '.'");

  /* Set the database version to 56. */

  set_db_version (56);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 56 to version 57.
 *
 * @return 0 success, -1 error.
 */
int
migrate_56_to_57 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 56. */

  if (manage_db_version () != 56)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* Ensure the new tables exist for the migrator. */

  sql ("CREATE TABLE IF NOT EXISTS escalator_condition_data"
       " (id INTEGER PRIMARY KEY, escalator INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS escalator_condition_data_trash"
       " (id INTEGER PRIMARY KEY, escalator INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS escalator_event_data"
       " (id INTEGER PRIMARY KEY, escalator INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS escalator_event_data_trash"
       " (id INTEGER PRIMARY KEY, escalator INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS escalator_method_data"
       " (id INTEGER PRIMARY KEY, escalator INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS escalator_method_data_trash"
       " (id INTEGER PRIMARY KEY, escalator INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS escalators"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  event INTEGER, condition INTEGER, method INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS escalators_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  event INTEGER, condition INTEGER, method INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS task_escalators"
       " (id INTEGER PRIMARY KEY, task INTEGER, escalator INTEGER,"
       "  escalator_location INTEGER);");

  /* Escalators were renamed to alerts. */

  sql ("CREATE TABLE alert_condition_data"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql_rename_column ("escalator_condition_data", "alert_condition_data",
                     "escalator", "alert");
  sql ("DROP TABLE escalator_condition_data;");

  /* Note: This is missing the escalator_condition_data_trash case.  It's so
   * long ago that anyone who was affected has probably worked through the
   * problem already, so I'm leaving it like this. */

  sql ("CREATE TABLE alert_event_data"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql_rename_column ("escalator_event_data", "alert_event_data",
                     "escalator", "alert");
  sql ("DROP TABLE escalator_event_data;");

  sql ("CREATE TABLE alert_event_data_trash"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql_rename_column ("escalator_event_data_trash", "alert_event_data_trash",
                     "escalator", "alert");
  sql ("DROP TABLE escalator_event_data_trash;");

  sql ("CREATE TABLE alert_method_data"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql_rename_column ("escalator_method_data", "alert_method_data",
                     "escalator", "alert");
  sql ("DROP TABLE escalator_method_data;");

  sql ("CREATE TABLE alert_method_data_trash"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql_rename_column ("escalator_method_data_trash", "alert_method_data_trash",
                     "escalator", "alert");
  sql ("DROP TABLE escalator_method_data_trash;");

  sql ("CREATE TABLE alerts"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  event INTEGER, condition INTEGER, method INTEGER);");
  sql_rename_column ("escalators", "alerts",
                     "escalator", "alert");
  sql ("DROP TABLE escalators;");

  sql ("CREATE TABLE alerts_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  event INTEGER, condition INTEGER, method INTEGER);");
  sql_rename_column ("escalators_trash", "alerts_trash",
                     "escalator", "alert");
  sql ("DROP TABLE escalators_trash;");

  sql ("CREATE TABLE task_alerts_56"
       " (id INTEGER PRIMARY KEY, task INTEGER, alert INTEGER,"
       "  escalator_location INTEGER);");
  sql_rename_column ("task_escalators", "task_alerts_56",
                     "escalator", "alert");
  sql ("DROP TABLE task_escalators;");

  sql ("CREATE TABLE task_alerts"
       " (id INTEGER PRIMARY KEY, task INTEGER, alert INTEGER,"
       "  alert_location INTEGER);");
  sql_rename_column ("task_alerts_56", "task_alerts",
                     "escalator_location", "alert_location");
  sql ("DROP TABLE task_alerts_56;");

  /* Set the database version to 57. */

  set_db_version (57);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 57 to version 58.
 *
 * @return 0 success, -1 error.
 */
int
migrate_57_to_58 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 57. */

  if (manage_db_version () != 57)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* Ensure the new tables exist for the migrator. */

  sql ("CREATE TABLE IF NOT EXISTS agents_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  installer TEXT, installer_64 TEXT, installer_filename,"
       "  installer_signature_64 TEXT, installer_trust INTEGER,"
       "  installer_trust_time, howto_install TEXT, howto_use TEXT);");

  /* Targets and agents got creation and modification times. */

  sql ("ALTER TABLE targets ADD COLUMN creation_time;");
  sql ("ALTER TABLE targets ADD COLUMN modification_time;");
  sql ("UPDATE targets SET creation_time = 0, modification_time = 0;");

  sql ("ALTER TABLE targets_trash ADD COLUMN creation_time;");
  sql ("ALTER TABLE targets_trash ADD COLUMN modification_time;");
  sql ("UPDATE targets_trash SET creation_time = 0, modification_time = 0;");

  sql ("ALTER TABLE agents ADD COLUMN creation_time;");
  sql ("ALTER TABLE agents ADD COLUMN modification_time;");
  sql ("UPDATE agents SET creation_time = 0, modification_time = 0;");

  sql ("ALTER TABLE agents_trash ADD COLUMN creation_time;");
  sql ("ALTER TABLE agents_trash ADD COLUMN modification_time;");
  sql ("UPDATE agents_trash SET creation_time = 0, modification_time = 0;");

  /* Set the database version to 58. */

  set_db_version (58);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 58 to version 59.
 *
 * @return 0 success, -1 error.
 */
int
migrate_58_to_59 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 58. */

  if (manage_db_version () != 58)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* Database version 55 introduced new UUIDs for the predefined report formats.
     Update the alert method data to use these new UUIDs. */

  sql ("UPDATE alert_method_data"
       " SET data = '5ceff8ba-1f62-11e1-ab9f-406186ea4fc5'"
       " WHERE data = 'a0704abb-2120-489f-959f-251c9f4ffebd';");

  sql ("UPDATE alert_method_data"
       " SET data = '6c248850-1f62-11e1-b082-406186ea4fc5'"
       " WHERE data = 'b993b6f5-f9fb-4e6e-9c94-dd46c00e058d';");

  sql ("UPDATE alert_method_data"
       " SET data = '77bd6c4a-1f62-11e1-abf0-406186ea4fc5'"
       " WHERE data = '929884c6-c2c4-41e7-befb-2f6aa163b458';");

  sql ("UPDATE alert_method_data"
       " SET data = '7fcc3a1a-1f62-11e1-86bf-406186ea4fc5'"
       " WHERE data = '9f1ab17b-aaaa-411a-8c57-12df446f5588';");

  sql ("UPDATE alert_method_data"
       " SET data = '9ca6fe72-1f62-11e1-9e7c-406186ea4fc5'"
       " WHERE data = 'f5c2a364-47d2-4700-b21d-0a7693daddab';");

  sql ("UPDATE alert_method_data"
       " SET data = 'a0b5bfb2-1f62-11e1-85db-406186ea4fc5'"
       " WHERE data = '1a60a67e-97d0-4cbf-bc77-f71b08e7043d';");

  sql ("UPDATE alert_method_data"
       " SET data = 'a3810a62-1f62-11e1-9219-406186ea4fc5'"
       " WHERE data = '19f6f1b3-7128-4433-888c-ccc764fe6ed5';");

  sql ("UPDATE alert_method_data"
       " SET data = 'a994b278-1f62-11e1-96ac-406186ea4fc5'"
       " WHERE data = 'd5da9f67-8551-4e51-807b-b6a873d70e34';");

  /* Set the database version to 59. */

  set_db_version (59);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 59 to version 60.
 *
 * @return 0 success, -1 error.
 */
int
migrate_59_to_60 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 59. */

  if (manage_db_version () != 59)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* Every task must now have an in_assets task preference. */

  sql ("INSERT INTO task_preferences (task, name, value)"
       " SELECT ROWID, 'in_assets', 'yes' FROM tasks;");

  /* Set the database version to 60. */

  set_db_version (60);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 60 to version 61.
 *
 * @return 0 success, -1 error.
 */
int
migrate_60_to_61 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 60. */

  if (manage_db_version () != 60)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* The alerts and alerts_trash tables got filter columns. */

  sql ("ALTER TABLE alerts ADD COLUMN filter INTEGER;");
  sql ("UPDATE alerts SET filter = 0;");

  sql ("ALTER TABLE alerts_trash ADD COLUMN filter INTEGER;");
  sql ("UPDATE alerts_trash SET filter = 0;");

  sql ("ALTER TABLE alerts_trash ADD COLUMN filter_location INTEGER;");
  sql ("UPDATE alerts_trash SET filter_location = 0;");

  /* Set the database version to 61. */

  set_db_version (61);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 61 to version 62.
 *
 * @return 0 success, -1 error.
 */
int
migrate_61_to_62 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 61. */

  if (manage_db_version () != 61)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* The reports table got count cache columns. */

  sql ("ALTER TABLE reports ADD COLUMN highs;");
  sql ("ALTER TABLE reports ADD COLUMN mediums;");
  sql ("ALTER TABLE reports ADD COLUMN lows;");
  sql ("ALTER TABLE reports ADD COLUMN logs;");
  sql ("ALTER TABLE reports ADD COLUMN fps;");
  sql ("ALTER TABLE reports ADD COLUMN override_highs;");
  sql ("ALTER TABLE reports ADD COLUMN override_mediums;");
  sql ("ALTER TABLE reports ADD COLUMN override_lows;");
  sql ("ALTER TABLE reports ADD COLUMN override_logs;");
  sql ("ALTER TABLE reports ADD COLUMN override_fps;");

  sql ("UPDATE reports SET highs = -1, override_highs = -1;");

  /* Set the database version to 62. */

  set_db_version (62);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 62 to version 63.
 *
 * @return 0 success, -1 error.
 */
int
migrate_62_to_63 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 62. */

  if (manage_db_version () != 62)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* Ensure the new tables exist for the migrator. */

  sql ("CREATE TABLE IF NOT EXISTS schedules_trash"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment,"
       "  first_time, period, period_months, duration);");

  /* The reports table got count cache columns. */

  sql ("ALTER TABLE schedules ADD COLUMN timezone;");
  sql ("ALTER TABLE schedules ADD COLUMN initial_offset;");

  sql ("UPDATE schedules"
       " SET timezone = (SELECT users.timezone FROM users"
       "                 WHERE ROWID = schedules.owner);");

  sql ("UPDATE schedules SET initial_offset = current_offset (timezone);");

  sql ("ALTER TABLE schedules_trash ADD COLUMN timezone;");
  sql ("ALTER TABLE schedules_trash ADD COLUMN initial_offset;");

  sql ("UPDATE schedules_trash"
       " SET timezone = (SELECT users.timezone FROM users"
       "                 WHERE ROWID = schedules_trash.owner);");

  sql ("UPDATE schedules_trash"
       " SET initial_offset = current_offset (timezone);");

  /* Set the database version to 63. */

  set_db_version (63);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 63 to version 64.
 *
 * @return 0 success, -1 error.
 */
int
migrate_63_to_64 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 63. */

  if (manage_db_version () != 63)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* The results table got a report column. */

  sql ("ALTER TABLE results ADD COLUMN report;");

  sql ("UPDATE results SET report = (SELECT report FROM report_results"
       "                             WHERE result = results.rowid);");

  sql ("CREATE INDEX IF NOT EXISTS results_by_report_host"
       " ON results (report, host);");

  /* Set the database version to 64. */

  set_db_version (64);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 64 to version 65.
 *
 * @return 0 success, -1 error.
 */
int
migrate_64_to_65 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 64. */

  if (manage_db_version () != 64)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* The report column on new results was left blank. */

  sql ("UPDATE results SET report = (SELECT report FROM report_results"
       "                             WHERE result = results.rowid);");

  sql ("REINDEX results_by_report_host;");

  /* Set the database version to 65. */

  set_db_version (65);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 65 to version 66.
 *
 * @return 0 success, -1 error.
 */
int
migrate_65_to_66 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 65. */

  if (manage_db_version () != 65)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* Schedules got creation and modification times. */

  sql ("ALTER TABLE schedules ADD COLUMN creation_time;");
  sql ("ALTER TABLE schedules ADD COLUMN modification_time;");
  sql ("UPDATE schedules SET creation_time = 0, modification_time = 0;");

  sql ("ALTER TABLE schedules_trash ADD COLUMN creation_time;");
  sql ("ALTER TABLE schedules_trash ADD COLUMN modification_time;");
  sql ("UPDATE schedules_trash SET creation_time = 0, modification_time = 0;");

  /* Set the database version to 66. */

  set_db_version (66);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 66 to version 67.
 *
 * @return 0 success, -1 error.
 */
int
migrate_66_to_67 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 66. */

  if (manage_db_version () != 66)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* Tasks got creation and modification times. */

  sql ("ALTER TABLE tasks ADD COLUMN creation_time;");
  sql ("ALTER TABLE tasks ADD COLUMN modification_time;");
  sql ("UPDATE tasks SET creation_time = 0, modification_time = 0;");

  /* Set the database version to 67. */

  set_db_version (67);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 67 to version 68.
 *
 * @return 0 success, -1 error.
 */
int
migrate_67_to_68 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 67. */

  if (manage_db_version () != 67)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* Ensure the new tables exist for the migrator. */

  sql ("CREATE TABLE IF NOT EXISTS slaves_trash"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment, host,"
       "  port, login, password);");

  /* Slaves got creation and modification times. */

  sql ("ALTER TABLE slaves ADD COLUMN creation_time;");
  sql ("ALTER TABLE slaves ADD COLUMN modification_time;");
  sql ("UPDATE slaves SET creation_time = 0, modification_time = 0;");

  sql ("ALTER TABLE slaves_trash ADD COLUMN creation_time;");
  sql ("ALTER TABLE slaves_trash ADD COLUMN modification_time;");
  sql ("UPDATE slaves_trash SET creation_time = 0, modification_time = 0;");

  /* Set the database version to 68. */

  set_db_version (68);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 68 to version 69.
 *
 * @return 0 success, -1 error.
 */
int
migrate_68_to_69 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 68. */

  if (manage_db_version () != 68)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* Ensure the new tables exist for the migrator. */

  sql ("CREATE TABLE IF NOT EXISTS report_formats_trash"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, extension,"
       "  content_type, summary, description, signature, trust INTEGER,"
       "  trust_time, flags INTEGER, original_uuid);");

  /* Schedules got creation and modification times. */

  sql ("ALTER TABLE report_formats ADD COLUMN creation_time;");
  sql ("ALTER TABLE report_formats ADD COLUMN modification_time;");
  sql ("UPDATE report_formats SET creation_time = 0, modification_time = 0;");

  sql ("ALTER TABLE report_formats_trash ADD COLUMN creation_time;");
  sql ("ALTER TABLE report_formats_trash ADD COLUMN modification_time;");
  sql ("UPDATE report_formats_trash SET"
       " creation_time = 0, modification_time = 0;");

  /* Set the database version to 69. */

  set_db_version (69);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 69 to version 70.
 *
 * @return 0 success, -1 error.
 */
int
migrate_69_to_70 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 69. */

  if (manage_db_version () != 69)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* Add creation and modification times to Port Lists. */

  sql ("ALTER TABLE port_lists ADD COLUMN creation_time;");
  sql ("ALTER TABLE port_lists ADD COLUMN modification_time;");
  sql ("UPDATE port_lists SET creation_time = 0, modification_time = 0;");

  sql ("ALTER TABLE port_lists_trash ADD COLUMN creation_time;");
  sql ("ALTER TABLE port_lists_trash ADD COLUMN modification_time;");
  sql ("UPDATE port_lists_trash SET"
       " creation_time = 0, modification_time = 0;");

  /* Set the database version to 70. */

  set_db_version (70);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 70 to version 71.
 *
 * @return 0 success, -1 error.
 */
int
migrate_70_to_71 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 70. */

  if (manage_db_version () != 70)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* Add creation and modification times to alerts. */

  sql ("ALTER TABLE alerts ADD COLUMN creation_time;");
  sql ("ALTER TABLE alerts ADD COLUMN modification_time;");
  sql ("UPDATE alerts SET creation_time = 0, modification_time = 0;");

  sql ("ALTER TABLE alerts_trash ADD COLUMN creation_time;");
  sql ("ALTER TABLE alerts_trash ADD COLUMN modification_time;");
  sql ("UPDATE alerts_trash SET"
       " creation_time = 0, modification_time = 0;");

  /* Set the database version to 71. */

  set_db_version (71);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 71 to version 72.
 *
 * @return 0 success, -1 error.
 */
int
migrate_71_to_72 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 71. */

  if (manage_db_version () != 71)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* Ensure the new tables exist for the migrator. */

  sql ("CREATE TABLE IF NOT EXISTS lsc_credentials_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, login,"
       "  password, comment, public_key TEXT, private_key TEXT, rpm TEXT,"
       "  deb TEXT, exe TEXT);");

  /* Add creation and modification times to LSC Credentials. */

  sql ("ALTER TABLE lsc_credentials ADD COLUMN creation_time;");
  sql ("ALTER TABLE lsc_credentials ADD COLUMN modification_time;");
  sql ("UPDATE lsc_credentials SET creation_time = 0, modification_time = 0;");

  sql ("ALTER TABLE lsc_credentials_trash ADD COLUMN creation_time;");
  sql ("ALTER TABLE lsc_credentials_trash ADD COLUMN modification_time;");
  sql ("UPDATE lsc_credentials_trash SET"
       " creation_time = 0, modification_time = 0;");

  /* Set the database version to 72. */

  set_db_version (72);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 72 to version 73.
 *
 * @return 0 success, -1 error.
 */
int
migrate_72_to_73 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 72. */

  if (manage_db_version () != 72)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* Ensure the new tables exist for the migrator. */

  sql ("CREATE TABLE IF NOT EXISTS configs_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name,"
       "  nvt_selector, comment, family_count INTEGER, nvt_count INTEGER,"
       "  families_growing INTEGER, nvts_growing INTEGER);");

  /* Add creation and modification times to Scan Configs. */

  sql ("ALTER TABLE configs ADD COLUMN creation_time;");
  sql ("ALTER TABLE configs ADD COLUMN modification_time;");
  sql ("UPDATE configs SET creation_time = 0, modification_time = 0;");

  sql ("ALTER TABLE configs_trash ADD COLUMN creation_time;");
  sql ("ALTER TABLE configs_trash ADD COLUMN modification_time;");
  sql ("UPDATE configs_trash SET creation_time = 0, modification_time = 0;");

  /* Set the database version to 73. */

  set_db_version (73);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 73 to version 74.
 *
 * @return 0 success, -1 error.
 */
int
migrate_73_to_74 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 73. */

  if (manage_db_version () != 73)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo ROLLBACK on failure. */

  /* Add creation and modification times to Scan Configs. */

  sql ("ALTER TABLE nvts ADD COLUMN uuid;");
  sql ("UPDATE nvts SET uuid = oid;");

  sql ("ALTER TABLE nvts ADD COLUMN comment;");
  sql ("UPDATE nvts SET comment = '';");

  sql ("ALTER TABLE nvts ADD COLUMN creation_time;");
  sql ("ALTER TABLE nvts ADD COLUMN modification_time;");
  sql ("UPDATE nvts SET"
       " creation_time = parse_time (tag (tag, 'creation_date')),"
       " modification_time = parse_time (tag (tag, 'last_modification'));");

  /* Set the database version to 74. */

  set_db_version (74);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 74 to version 75.
 *
 * @return 0 success, -1 error.
 */
int
migrate_74_to_75 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 74. */

  if (manage_db_version () != 74)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Ensure the tables exist for the migrator. */

  sql ("CREATE TABLE IF NOT EXISTS permissions"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
       "  resource_type, resource, resource_uuid, resource_location,"
       "  subject_type, subject, creation_time, modification_time);");

  sql ("CREATE TABLE IF NOT EXISTS task_users"
       " (id INTEGER PRIMARY KEY, task INTEGER, user INTEGER,"
       "  actions INTEGER);");

  /** @todo ROLLBACK on failure. */

  /* Task observers are now handled by permissions. */

  sql ("INSERT INTO permissions"
       " (uuid, owner, name, comment, resource_type, resource, resource_uuid,"
       "  resource_location, subject_type, subject, creation_time,"
       "  modification_time)"
       " SELECT make_uuid (),"
       "        (SELECT owner FROM tasks WHERE ROWID = task),"
       "        'get', '', 'task', task,"
       "        (SELECT uuid FROM tasks WHERE ROWID = task),"
       "        " G_STRINGIFY (LOCATION_TABLE) ", 'user', user, now (), now ()"
       " FROM task_users;");

  sql ("DROP TABLE task_users;");

  /* Set the database version to 75. */

  set_db_version (75);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 75 to version 76.
 *
 * @return 0 success, -1 error.
 */
int
migrate_75_to_76 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 75. */

  if (manage_db_version () != 75)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Delete any nvts_checksum leftovers. */
  sql ("DELETE FROM main.meta WHERE name = \"nvts_checksum\";");

  /* Rename nvts_md5sum into nvts_feed_version */
  sql ("UPDATE main.meta SET name = \"nvts_feed_version\""
       " WHERE name = \"nvts_md5sum\";");

  /* Set the database version to 76. */

  set_db_version (76);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 76 to version 77.
 *
 * @return 0 success, -1 error.
 */
int
migrate_76_to_77 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 76. */

  if (manage_db_version () != 76)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Users got standard columns, and columns to mirror info stored on disk. */

  sql ("ALTER TABLE users ADD COLUMN owner;");
  sql ("ALTER TABLE users ADD COLUMN comment;");
  sql ("ALTER TABLE users ADD COLUMN creation_time;");
  sql ("ALTER TABLE users ADD COLUMN modification_time;");
  sql ("ALTER TABLE users ADD COLUMN role;");
  sql ("ALTER TABLE users ADD COLUMN hosts;");
  sql ("ALTER TABLE users ADD COLUMN hosts_allow;");
  sql ("UPDATE users SET"
       " owner = NULL,"
       " comment = '',"
       " creation_time = 0,"
       " modification_time = 0,"
       /* These are temporary, and only used for clone. */
       " role = 'User',"
       " hosts = '',"
       " hosts_allow = 2;");

  /* Set the database version to 77. */

  set_db_version (77);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 77 to version 78.
 *
 * @return 0 success, -1 error.
 */
int
migrate_77_to_78 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 77. */
  if (manage_db_version () != 77)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Set schedule durations and periods to 0 if they were -1,
     which was the old default value of the create_schedule command. */
  sql ("UPDATE schedules"
       " SET duration = 0"
       " WHERE duration = -1;");

  sql ("UPDATE schedules"
       " SET period = 0"
       " WHERE period = -1;");

  sql ("UPDATE schedules_trash"
       " SET duration = 0"
       " WHERE duration = -1;");

  sql ("UPDATE schedules_trash"
       " SET period = 0"
       " WHERE period = -1;");

  /* Set the database version to 78. */

  set_db_version (78);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 78 to version 79.
 *
 * @return 0 success, -1 error.
 */
int
migrate_78_to_79 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 78. */

  if (manage_db_version () != 78)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Remove tcp timestamps nvt from Discovery Scan Config. */

  sql ("DELETE FROM nvt_selectors WHERE "
       " name='" MANAGE_NVT_SELECTOR_UUID_DISCOVERY "'"
       " AND family_or_nvt='1.3.6.1.4.1.25623.1.0.80091';");

  /* Add preferences for "Ping Host" nvt in Discovery Scan Config. */
  sql ("INSERT INTO config_preferences (config, type, name, value)"
       " VALUES ((SELECT ROWID FROM configs WHERE uuid = '"
                  CONFIG_UUID_DISCOVERY "'),"
       "         'PLUGINS_PREFS',"
       "         'Ping Host[checkbox]:Mark unrechable Hosts as dead (not scanning)',"
       " 'yes');");
  sql ("INSERT INTO config_preferences (config, type, name, value)"
       " VALUES ((SELECT ROWID FROM configs WHERE uuid = '"
                  CONFIG_UUID_DISCOVERY "'),"
       "         'PLUGINS_PREFS',"
       "         'Ping Host[checkbox]:Report about unrechable Hosts',"
       "         'yes');");

  /* Add preferences for "Services" nvt in Discovery Scan Config. */
  sql ("INSERT INTO config_preferences (config, type, name, value)"
       " VALUES ((SELECT ROWID FROM configs WHERE uuid = '"
                  CONFIG_UUID_DISCOVERY "'),"
       "         'PLUGINS_PREFS',"
       "         'Services[radio]:Test SSL based services',"
       "         'All;Known SSL ports;None');");

  /* Set the database version to 79. */

  set_db_version (79);

  sql ("COMMIT;");

  return 0;
}

#define MIGRATE_79_to_80_DELETE(table)                                \
 sql ("DELETE FROM " table                                            \
      " WHERE owner IN (SELECT ROWID FROM users WHERE %s);",          \
      where)

/**
 * @brief Delete users according to a condition.
 *
 * @param[in]  where  Where clause.
 */
void
migrate_79_to_80_remove_users (const char *where)
{
  /* Remove everything that is owned by the user. */
  MIGRATE_79_to_80_DELETE ("agents");
  MIGRATE_79_to_80_DELETE ("agents_trash");
  sql ("DELETE FROM config_preferences"
       " WHERE config IN (SELECT ROWID FROM configs"
       "                  WHERE owner IN (SELECT ROWID FROM users"
       "                                  WHERE %s));",
       where);
  sql ("DELETE FROM config_preferences_trash"
       " WHERE config IN (SELECT ROWID FROM configs"
       "                  WHERE owner IN (SELECT ROWID FROM users"
       "                                  WHERE %s));",
       where);
  sql ("DELETE FROM nvt_selectors"
       " WHERE name IN (SELECT nvt_selector FROM configs"
       "                WHERE owner IN (SELECT ROWID FROM users"
       "                                WHERE %s));",
       where);
  MIGRATE_79_to_80_DELETE ("configs");
  MIGRATE_79_to_80_DELETE ("configs_trash");
  sql ("DELETE FROM alert_condition_data"
       " WHERE alert IN (SELECT ROWID FROM alerts"
       "                 WHERE owner IN (SELECT ROWID FROM users"
       "                                 WHERE %s));",
       where);
  sql ("DELETE FROM alert_condition_data_trash"
       " WHERE alert IN (SELECT ROWID FROM alerts_trash"
       "                 WHERE owner IN (SELECT ROWID FROM users"
       "                                 WHERE %s));",
       where);
  sql ("DELETE FROM alert_event_data"
       " WHERE alert IN (SELECT ROWID FROM alerts"
       "                 WHERE owner IN (SELECT ROWID FROM users"
       "                                 WHERE %s));",
       where);
  sql ("DELETE FROM alert_event_data_trash"
       " WHERE alert IN (SELECT ROWID FROM alerts_trash"
       "                 WHERE owner IN (SELECT ROWID FROM users"
       "                                 WHERE %s));",
       where);
  sql ("DELETE FROM alert_method_data"
       " WHERE alert IN (SELECT ROWID FROM alerts"
       "                 WHERE owner IN (SELECT ROWID FROM users"
       "                                 WHERE %s));",
       where);
  sql ("DELETE FROM alert_method_data_trash"
       " WHERE alert IN (SELECT ROWID FROM alerts_trash"
       "                 WHERE owner IN (SELECT ROWID FROM users"
       "                                 WHERE %s));",
       where);
  MIGRATE_79_to_80_DELETE ("alerts");
  MIGRATE_79_to_80_DELETE ("alerts_trash");
  MIGRATE_79_to_80_DELETE ("filters");
  MIGRATE_79_to_80_DELETE ("filters_trash");
  sql ("DELETE FROM group_users"
       " WHERE `group` IN (SELECT ROWID FROM groups"
       "                   WHERE owner IN (SELECT ROWID FROM users"
       "                                   WHERE %s));",
       where);
  MIGRATE_79_to_80_DELETE ("groups");
  MIGRATE_79_to_80_DELETE ("lsc_credentials");
  MIGRATE_79_to_80_DELETE ("lsc_credentials_trash");
  MIGRATE_79_to_80_DELETE ("notes");
  MIGRATE_79_to_80_DELETE ("notes_trash");
  MIGRATE_79_to_80_DELETE ("overrides");
  MIGRATE_79_to_80_DELETE ("overrides_trash");
  MIGRATE_79_to_80_DELETE ("permissions");
  MIGRATE_79_to_80_DELETE ("permissions_trash");
  MIGRATE_79_to_80_DELETE ("port_lists");
  MIGRATE_79_to_80_DELETE ("port_lists_trash");
  sql ("DELETE FROM port_ranges"
       " WHERE port_list IN (SELECT ROWID FROM port_lists"
       "                     WHERE owner IN (SELECT ROWID FROM users"
       "                                     WHERE %s));",
       where);
  sql ("DELETE FROM port_ranges_trash"
       " WHERE port_list IN (SELECT ROWID FROM port_lists_trash"
       "                     WHERE owner IN (SELECT ROWID FROM users"
       "                                     WHERE %s));",
       where);
  sql ("DELETE FROM report_format_param_options"
       " WHERE report_format_param"
       "       IN (SELECT ROWID FROM report_format_params"
       "           WHERE report_format"
       "                 IN (SELECT ROWID FROM report_formats"
       "                     WHERE owner IN (SELECT ROWID FROM users"
       "                                     WHERE %s)));",
       where);
  sql ("DELETE FROM report_format_param_options_trash"
       " WHERE report_format_param"
       "       IN (SELECT ROWID FROM report_format_params_trash"
       "           WHERE report_format"
       "                 IN (SELECT ROWID FROM report_formats"
       "                     WHERE owner IN (SELECT ROWID FROM users"
       "                                     WHERE %s)));",
       where);
  sql ("DELETE FROM report_format_params"
       " WHERE report_format IN (SELECT ROWID FROM report_formats"
       "                         WHERE owner IN (SELECT ROWID FROM users"
       "                                         WHERE %s));",
       where);
  sql ("DELETE FROM report_format_params_trash"
       " WHERE report_format IN (SELECT ROWID FROM report_formats"
       "                         WHERE owner IN (SELECT ROWID FROM users"
       "                                         WHERE %s));",
       where);
  MIGRATE_79_to_80_DELETE ("report_formats");
  MIGRATE_79_to_80_DELETE ("report_formats_trash");
  sql ("DELETE FROM report_host_details"
       " WHERE report_host"
       "       IN (SELECT ROWID FROM report_hosts"
       "           WHERE report IN (SELECT ROWID FROM reports"
       "                            WHERE owner IN (SELECT ROWID FROM users"
       "                                            WHERE %s)));",
       where);
  sql ("DELETE FROM report_results"
       " WHERE report IN (SELECT ROWID FROM reports"
       "                  WHERE owner IN (SELECT ROWID FROM users"
       "                                  WHERE %s));",
       where);
  sql ("DELETE FROM results"
       " WHERE report IN (SELECT ROWID FROM reports"
       "                  WHERE owner IN (SELECT ROWID FROM users"
       "                                  WHERE %s));",
       where);
  MIGRATE_79_to_80_DELETE ("reports");
  MIGRATE_79_to_80_DELETE ("schedules");
  MIGRATE_79_to_80_DELETE ("schedules_trash");
  MIGRATE_79_to_80_DELETE ("slaves");
  MIGRATE_79_to_80_DELETE ("slaves_trash");
  MIGRATE_79_to_80_DELETE ("settings");
  MIGRATE_79_to_80_DELETE ("tags");
  MIGRATE_79_to_80_DELETE ("tags_trash");
  MIGRATE_79_to_80_DELETE ("targets");
  MIGRATE_79_to_80_DELETE ("targets_trash");
  sql ("DELETE FROM task_files"
       " WHERE task IN (SELECT ROWID FROM tasks"
       "                WHERE owner IN (SELECT ROWID FROM users"
       "                                WHERE %s));",
       where);
  sql ("DELETE FROM task_alerts"
       " WHERE task IN (SELECT ROWID FROM tasks"
       "                WHERE owner IN (SELECT ROWID FROM users"
       "                                WHERE %s));",
       where);
  sql ("DELETE FROM task_preferences"
       " WHERE task IN (SELECT ROWID FROM tasks"
       "                WHERE owner IN (SELECT ROWID FROM users"
       "                                WHERE %s));",
       where);
  MIGRATE_79_to_80_DELETE ("tasks");
  sql ("DELETE FROM users WHERE %s;",
       where);
}

#define RULES_HEADER "# This file is managed by the OpenVAS Administrator.\n# Any modifications must keep to the format that the Administrator expects.\n"

/**
 * @brief Get access information for a user.
 *
 * @param[in]   user_dir     The directory containing the user.
 * @param[out]  hosts        The hosts the user is allowed/forbidden to scan.
 * @param[out]  hosts_allow  0 forbidden, 1 allowed, 2 all allowed, 3 custom.
 *
 * @return 0 success, -1 error.
 */
int
migrate_79_to_80_user_access (const gchar *user_dir, gchar ** hosts,
                              int *hosts_allow)
{
  gchar *rules_file, *rules;
  GError *error = NULL;

  assert (hosts != NULL);
  assert (hosts_allow != NULL);

  rules_file = g_build_filename (user_dir, "auth", "rules", NULL);
  if (g_file_test (rules_file, G_FILE_TEST_EXISTS) == FALSE)
    {
      *hosts = NULL;
      *hosts_allow = 2;
      return 0;
    }

  g_file_get_contents (rules_file, &rules, NULL, &error);
  if (error)
    {
      g_warning ("%s", error->message);
      g_error_free (error);
      g_free (rules_file);
      return -1;
    }
  g_free (rules_file);

  if (strlen (rules))
    {
      int count, end = 0;

      /* "# " ("allow " | "deny ") hosts */

      count = sscanf (rules, RULES_HEADER "# allow %*[^\n]%n\n", &end);
      if (count == 0 && end > 0)
        {
          *hosts =
            g_strndup (rules + strlen (RULES_HEADER "# allow "),
                       end - strlen (RULES_HEADER "# allow "));
          *hosts_allow = 1;
          g_free (rules);
          return 0;
        }

      count = sscanf (rules, RULES_HEADER "# deny %*[^\n]%n\n", &end);
      if (count == 0 && end > 0)
        {
          *hosts =
            g_strndup (rules + strlen (RULES_HEADER "# deny "),
                       end - strlen (RULES_HEADER "# deny "));
          *hosts_allow = 0;
          g_free (rules);
          return 0;
        }

      if (strcmp (RULES_HEADER, rules) == 0)
        {
          *hosts = NULL;
          *hosts_allow = 2;
          g_free (rules);
          return 0;
        }

      /* Failed to parse content. */
      *hosts = NULL;
      *hosts_allow = 3;
      g_free (rules);
      return 0;
    }

  *hosts = NULL;
  *hosts_allow = 2;
  g_free (rules);
  return 0;
}

/**
 * @brief Migrate the database from version 79 to version 80.
 *
 * @return 0 success, -1 error.
 */
int
migrate_79_to_80 ()
{
  struct dirent **names;
  int count, index;
  array_t *dirs;
  gchar *dir;
  struct stat state;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 79. */

  if (manage_db_version () != 79)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Ensure that all tables exists. */
  sql ("CREATE TABLE IF NOT EXISTS alert_condition_data_trash"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS config_preferences_trash"
       " (id INTEGER PRIMARY KEY, config INTEGER, type, name, value);");
  sql ("CREATE TABLE IF NOT EXISTS groups"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS group_users"
       " (id INTEGER PRIMARY KEY, `group` INTEGER, user INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS filters"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  type, term, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS filters_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  type, term, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS notes_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt,"
       "  creation_time, modification_time, text, hosts, port, threat,"
       "  task INTEGER, result INTEGER, end_time);");
  sql ("CREATE TABLE IF NOT EXISTS overrides_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt,"
       "  creation_time, modification_time, text, hosts, port, threat,"
       "  new_threat, task INTEGER, result INTEGER, end_time);");
  sql ("CREATE TABLE IF NOT EXISTS permissions"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
       "  resource_type, resource, resource_uuid, resource_location,"
       "  subject_type, subject, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS permissions_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
       "  resource_type, resource, resource_uuid, resource_location,"
       "  subject_type, subject, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS port_names"
       " (id INTEGER PRIMARY KEY, number INTEGER, protocol, name,"
       "  UNIQUE (number, protocol) ON CONFLICT REPLACE);");
  sql ("CREATE TABLE IF NOT EXISTS report_format_params_trash"
       " (id INTEGER PRIMARY KEY, report_format, name, type INTEGER, value,"
       "  type_min, type_max, type_regex, fallback);");
  sql ("CREATE TABLE IF NOT EXISTS report_format_param_options_trash"
       " (id INTEGER PRIMARY KEY, report_format_param, value);");
  sql ("CREATE TABLE IF NOT EXISTS settings"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment, value);");
  sql ("CREATE TABLE IF NOT EXISTS tags"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
       "  creation_time, modification_time, attach_type, attach_id,"
       "  active, value);");
  sql ("CREATE TABLE IF NOT EXISTS tags_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
       "  creation_time, modification_time, attach_type, attach_id,"
       "  active, value);");

  /* Users got new column "method".  User data moved from disk to database. */

  sql ("ALTER TABLE users ADD COLUMN method;");
  sql ("UPDATE users SET method = 'file';");

  count = scandir (OPENVAS_STATE_DIR "/users", &names, NULL, alphasort);
  if (count < 0)
    {
      g_warning ("%s: failed to open dir %s/users: %s\n",
                 __FUNCTION__,
                 OPENVAS_STATE_DIR,
                 strerror (errno));
      sql ("ROLLBACK;");
      return -1;
    }

  dirs = make_array ();

  /* Set a flag on every user, to see which are left over. */

  sql ("UPDATE users SET password = -1;");

  /* Update db users from classic classic users, checking for ldap_connect at
   * the same time.  Assume that all ldap_connect users have at least one
   * classic user of the same name.  Remove all other users, both from disk
   * and from the db.  Remove special user "om" from the database.  */

  for (index = 0; index < count; index++)
    {
      gchar *role, *role_file, *uuid, *uuid_file, *classic_dir, *remote_dir;
      gchar *hash, *hosts, *quoted_hash, *quoted_hosts, *quoted_method;
      gchar *quoted_name, *quoted_uuid, *where, *file, *remote_flag_file;
      auth_method_t method;
      GError *error;
      user_t user;
      int hosts_allow;

      if ((strcmp (names[index]->d_name, ".") == 0)
          || (strcmp (names[index]->d_name, "..") == 0)
          || (strcmp (names[index]->d_name, "om") == 0))
        {
          free (names[index]);
          continue;
        }

      /* Figure out the user dir. */

      remote_dir = g_build_filename (OPENVAS_STATE_DIR,
                                     "users-remote",
                                     "ldap_connect",
                                     names[index]->d_name,
                                     NULL);
      classic_dir = g_build_filename (OPENVAS_STATE_DIR, "users",
                                      names[index]->d_name,
                                      NULL);
      remote_flag_file = g_build_filename (classic_dir,
                                           "auth",
                                           "methods",
                                           "ldap_connect",
                                           NULL);
      tracef ("          user: %s\n", names[index]->d_name);
      tracef ("    remote dir: %s\n", remote_dir);
      tracef ("   classic dir: %s\n", classic_dir);
      tracef ("     flag file: %s\n", remote_flag_file);
      if (g_file_test (remote_dir, G_FILE_TEST_IS_DIR)
          && g_file_test (remote_flag_file, G_FILE_TEST_EXISTS))
        method = AUTHENTICATION_METHOD_LDAP_CONNECT;
      else
        {
          g_free (remote_dir);
          method = AUTHENTICATION_METHOD_FILE;
          if (g_file_test (classic_dir, G_FILE_TEST_IS_DIR) == FALSE)
            {
              free (names[index]);
              g_free (classic_dir);
              g_free (remote_flag_file);
              continue;
            }
          remote_dir = g_strdup (classic_dir);
        }
      g_free (remote_flag_file);

      /* Get UUID from file. */

      uuid_file = g_build_filename (remote_dir, "uuid", NULL);
      error = NULL;
      g_file_get_contents (uuid_file,
                           &uuid,
                           NULL,
                           &error);
      if (error)
        {
          g_warning ("%s: Failed to read %s: %s\n",
                     __FUNCTION__,
                     uuid_file,
                     error->message);
          g_free (classic_dir);
          g_free (remote_dir);
          g_free (uuid_file);
          g_error_free (error);
          sql ("ROLLBACK;");
          return -1;
        }
      g_free (uuid_file);

      /* Check UUID. */

      if (uuid == NULL || strlen (g_strchomp (uuid)) != 36)
        {
          g_warning ("%s: Error in UUID: %s\n",
                     __FUNCTION__,
                     uuid);
          g_free (classic_dir);
          g_free (remote_dir);
          g_free (uuid);
          sql ("ROLLBACK;");
          return -1;
        }
      tracef ("          uuid: %s\n", uuid);

      /* Get role. */

      role = "User";

      role_file = g_build_filename (remote_dir, "isobserver", NULL);
      if (g_file_test (role_file, G_FILE_TEST_EXISTS))
        role = "Observer";
      g_free (role_file);

      role_file = g_build_filename (remote_dir, "isadmin", NULL);
      if (g_file_test (role_file, G_FILE_TEST_EXISTS))
        role = "Admin";
      g_free (role_file);

      /* Find user in db. */

      quoted_uuid = sql_quote (uuid);
      switch (sql_int64 (&user, 0, 0,
                         "SELECT ROWID FROM users WHERE uuid = '%s';",
                         quoted_uuid))
        {
          case 0:
            break;
          case 1:        /* Too few rows in result of query. */
            quoted_name = sql_quote (names[index]->d_name);
            sql ("INSERT INTO users"
                 " (uuid, owner, name, comment, password, timezone, method,"
                 "  hosts, hosts_allow)"
                 " VALUES"
                 " ('%s', NULL, '%s', '', NULL, NULL, 'file', '', 2);",
                 quoted_uuid,
                 quoted_name);
            g_free (quoted_name);
            user = sqlite3_last_insert_rowid (task_db);
            break;
          default:       /* Programming error. */
            assert (0);
          case -1:
            g_warning ("%s: Error finding user %s\n",
                       __FUNCTION__,
                       uuid);
            g_free (uuid);
            g_free (quoted_uuid);
            g_free (classic_dir);
            g_free (remote_dir);
            sql ("ROLLBACK;");
            return -1;
            break;
        }

      /* Get hash. */

      file = g_build_filename (classic_dir, "auth", "hash", NULL);
      error = NULL;
      if (file && g_file_test (file, G_FILE_TEST_EXISTS))
        {
          g_file_get_contents (file,
                               &hash,
                               NULL,
                               &error);
          if (error)
            {
              g_warning ("%s: Failed to read %s: %s\n",
                         __FUNCTION__,
                         file,
                         error->message);
              g_free (classic_dir);
              g_free (remote_dir);
              g_free (quoted_uuid);
              g_free (file);
              g_error_free (error);
              sql ("ROLLBACK;");
              return -1;
            }
          assert (hash);
          g_strchomp (hash);
        }
      else
        hash = NULL;
      g_free (file);

      /* Get host access rules. */

      hosts = NULL;
      hosts_allow = 2;
      if (migrate_79_to_80_user_access (classic_dir, &hosts, &hosts_allow))
        {
          g_warning ("%s: Failed to get user rules from %s\n",
                     __FUNCTION__,
                     classic_dir);
          g_free (classic_dir);
          g_free (remote_dir);
          g_free (quoted_uuid);
          g_error_free (error);
          sql ("ROLLBACK;");
          return -1;
        }

      if (hosts_allow == 3)
        /* If they were custom rules, just make is allow all. */
        hosts_allow = 2;

      /* Update db from disk. */

      quoted_method = sql_quote (auth_method_name (method));
      quoted_hash = sql_quote (hash ? hash : "");
      quoted_hosts = sql_quote (hosts ? hosts : "");
      sql ("UPDATE users"
           " SET role = '%s',"
           "     uuid = '%s',"
           "     method = '%s',"
           "     password = %s%s%s,"
           "     hosts = '%s',"
           "     hosts_allow = %i"
           " WHERE ROWID = %llu;",
           role,
           quoted_uuid,
           quoted_method,
           hash ? "'" : "",
           hash ? quoted_hash : "NULL",
           hash ? "'" : "",
           quoted_hosts,
           hosts_allow,
           user);
      g_free (quoted_uuid);
      g_free (quoted_method);
      g_free (quoted_hash);
      g_free (quoted_hosts);

      /* Remove all other users with this name from the db. */

      quoted_name = sql_quote (names[index]->d_name);
      where = g_strdup_printf ("name = '%s' AND ROWID != %llu",
                               quoted_name,
                               user);
      g_free (quoted_name);
      migrate_79_to_80_remove_users (where);
      g_free (where);

      /* Store user directory for removal after last possible ROLLBACK. */

      array_add (dirs, classic_dir);

      free (names[index]);
    }
  free (names);

  /* TODO To preserve ldap and ads, create db entries here. */

  /* Remove remaining users. */

  migrate_79_to_80_remove_users ("password = -1");

  /* Remove entire user-remote dir. */

  dir = g_build_filename (OPENVAS_STATE_DIR, "users-remote", NULL);
  if (g_lstat (dir, &state))
    {
      if (errno != ENOENT)
        g_warning ("%s: g_lstat (%s) failed: %s\n",
                   __FUNCTION__, dir, g_strerror (errno));
    }
  else
    openvas_file_remove_recurse (dir);

  g_free (dir);

  /* Remove user dirs. */

  for (index = 0; index < dirs->len; index++)
    openvas_file_remove_recurse (g_ptr_array_index (dirs, index));
  array_free (dirs);

  /* Set the database version to 80. */

  set_db_version (80);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 80 to version 81.
 *
 * @return 0 success, -1 error.
 */
int
migrate_80_to_81 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 80. */

  if (manage_db_version () != 80)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Ensure new tables exist. */
  sql ("CREATE TABLE IF NOT EXISTS roles"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS role_users"
       " (id INTEGER PRIMARY KEY, role INTEGER, user INTEGER);");

  /* User roles moved to their own table. */

  sql ("INSERT INTO roles"
       " (uuid, owner, name, comment, creation_time, modification_time)"
       " VALUES"
       " ('" ROLE_UUID_ADMIN "', NULL, 'Admin', 'Administrator', now (),"
       "  now ());");

  sql ("INSERT INTO roles"
       " (uuid, owner, name, comment, creation_time, modification_time)"
       " VALUES"
       " ('" ROLE_UUID_USER "', NULL, 'User', 'User', now (), now ());");

  sql ("INSERT INTO roles"
       " (uuid, owner, name, comment, creation_time, modification_time)"
       " VALUES"
       " ('" ROLE_UUID_OBSERVER "', NULL, 'Observer', 'Observer', now (),"
       "  now ());");

  sql ("INSERT INTO role_users (role, user)"
       " SELECT (SELECT ROWID FROM roles WHERE roles.name = users.role),"
       "        users.ROWID"
       " FROM users;");

  sql ("UPDATE users SET role = NULL;");

  /* Set the database version to 81. */

  set_db_version (81);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 81 to version 82.
 *
 * @return 0 success, -1 error.
 */
int
migrate_81_to_82 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 80. */

  if (manage_db_version () != 81)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Changes are already done by init_manage */

  /* Set the database version to 82. */

  set_db_version (82);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 82 to version 83.
 *
 * @return 0 success, -1 error.
 */
int
migrate_82_to_83 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 82. */

  if (manage_db_version () != 82)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Remove risk_factor from NVTs table. */

  /* Move the table away. */

  sql ("ALTER TABLE nvts RENAME TO nvts_82;");

  /* Create the table in the new format. */

  sql ("CREATE TABLE IF NOT EXISTS nvts"
       " (id INTEGER PRIMARY KEY, uuid, oid, version, name, comment, summary,"
       "  description, copyright, cve, bid, xref, tag, sign_key_ids,"
       "  category INTEGER, family, cvss_base, creation_time,"
       "  modification_time);");

  /* Copy the data into the new table. */

  sql ("INSERT into nvts"
       " (id, uuid, oid, version, name, comment, summary, description,"
       "  copyright, cve, bid, xref, tag, sign_key_ids, category, family,"
       "  cvss_base, creation_time, modification_time)"
       " SELECT"
       "  id, uuid, oid, version, name, comment, summary, description,"
       "  copyright, cve, bid, xref, tag, sign_key_ids, category, family,"
       "  cvss_base, creation_time, modification_time"
       " FROM nvts_82;");

  /* Drop the old table. */

  sql ("DROP TABLE nvts_82;");

  /* Set the database version to 83. */

  set_db_version (83);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 83 to version 84.
 *
 * @return 0 success, -1 error.
 */
int
migrate_83_to_84 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 83. */

  if (manage_db_version () != 83)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */
  /* Add columns "nvt_revision" and "severity" to results table */
  sql ("ALTER TABLE results ADD COLUMN nvt_version;");
  sql ("ALTER TABLE results ADD COLUMN severity REAL;");

  /* Set the database version to 84. */

  set_db_version (84);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 84 to version 85.
 *
 * @return 0 success, -1 error.
 */
int
migrate_84_to_85 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 84. */

  if (manage_db_version () != 84)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */
  /* Add columns "severity" and "override_severity" to reports table */
  sql ("ALTER TABLE reports ADD COLUMN severity REAL;");
  sql ("ALTER TABLE reports ADD COLUMN override_severity REAL;");

  /* Clear counts cache so the severity columns are updated */
  sql ("UPDATE reports SET highs = -1;");
  sql ("UPDATE reports SET override_highs = -1;");

  /* Set the database version to 85. */

  set_db_version (85);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 85 to version 86.
 *
 * @return 0 success, -1 error.
 */
int
migrate_85_to_86 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 85. */

  if (manage_db_version () != 85)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */
  /* Add column "new_severity" to overrides and overrides_trash */
  sql ("ALTER TABLE overrides ADD COLUMN new_severity REAL;");
  sql ("ALTER TABLE overrides_trash ADD COLUMN new_severity REAL;");

  /* Clear counts cache so the severity columns are updated */
  sql ("UPDATE reports SET override_highs = -1;");

  /* Set the database version to 86. */

  set_db_version (86);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 86 to version 87.
 *
 * @return 0 success, -1 error.
 */
int
migrate_86_to_87 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 86. */

  if (manage_db_version () != 86)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The scanner message types "Security Hole", "Security Warning" and
   * "Security Note" were merged into a single type, "Alarm".
   *
   * Update the severity of old high, medium and low results at the same
   * time, because the severity of these results can only be determined by
   * their message type. */

  sql ("UPDATE results"
       " SET severity = (CASE type"
       "                 WHEN 'Security Hole' THEN 10.0"
       "                 WHEN 'Security Warning' THEN 5.0"
       "                 WHEN 'Security Note' THEN 2.0"
       "                 WHEN 'Log Message' THEN 0.0"
       "                 ELSE NULL END)"
       " WHERE severity IS NULL;");

  sql ("UPDATE results SET type = 'Alarm'"
       " WHERE type = 'Security Hole'"
       " OR type = 'Security Warning'"
       " OR type = 'Security Note';");

  /* Set the database version to 87. */

  set_db_version (87);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 87 to version 88.
 *
 * @return 0 success, -1 error.
 */
int
migrate_87_to_88 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 87. */

  if (manage_db_version () != 87)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Rename reports table */
  sql ("ALTER TABLE reports RENAME TO reports_87;");
  /* Create a new one without severity and counts. */
  sql ("CREATE TABLE IF NOT EXISTS reports"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, hidden INTEGER,"
       "  task INTEGER, date INTEGER, start_time, end_time, nbefile, comment,"
       "  scan_run_status INTEGER, slave_progress, slave_task_uuid);");
  /* Create a new dedicated report_counts table. */
  sql ("CREATE TABLE IF NOT EXISTS report_counts"
       " (id INTEGER PRIMARY KEY, report INTEGER, user INTEGER,"
       "  severity, override_severity, highs, mediums, lows, logs, fps,"
       "  override_highs, override_mediums, override_lows, override_logs,"
       "  override_fps);");
  /* Copy old report data to new reports table. */
  sql ("INSERT INTO reports"
       " (id, uuid, owner, hidden, task, date, start_time, end_time,"
       "  nbefile, comment, scan_run_status, slave_progress, slave_task_uuid)"
       " SELECT id, uuid, owner, hidden, task, date, start_time, end_time,"
       "  nbefile, comment, scan_run_status, slave_progress, slave_task_uuid"
       " FROM reports_87;");
  /* Delete old results table. */
  sql ("DROP TABLE reports_87;");

  /* Set the database version to 88. */

  set_db_version (88);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 88 to version 89.
 *
 * @return 0 success, -1 error.
 */
int
migrate_88_to_89 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 87. */

  if (manage_db_version () != 88)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Rename overrides tables */
  sql ("ALTER TABLE overrides RENAME TO overrides_88;");
  sql ("ALTER TABLE overrides_trash RENAME TO overrides_trash_88;");

  /* Create a new one without threat and new_threat. */
  sql ("CREATE TABLE IF NOT EXISTS overrides"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt,"
       "  creation_time, modification_time, text, hosts, port, severity,"
       "  new_severity, task INTEGER, result INTEGER, end_time);");

  sql ("CREATE TABLE IF NOT EXISTS overrides_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt,"
       "  creation_time, modification_time, text, hosts, port, severity,"
       "  new_severity, task INTEGER, result INTEGER, end_time);");

  /* Migrate old override data to new tables. */
  sql ("INSERT INTO overrides"
       " (id, uuid, owner, nvt, creation_time, modification_time, text,"
       "  hosts, port, severity, new_severity, task, result, end_time)"
       " SELECT id, uuid, owner, nvt, creation_time, modification_time, text,"
       "   hosts, port,"
       "   (CASE threat"
       "    WHEN 'Security Hole' THEN 0.1"
       "    WHEN 'Security Warning' THEN 0.1"
       "    WHEN 'Security Note' THEN 0.1"
       "    WHEN 'Alarm' THEN 0.1"
       "    WHEN 'Log Message' THEN 0.0"
       "    WHEN 'False Positive' THEN -1.0"
       "    WHEN 'Debug Message' THEN -2.0"
       "    WHEN 'Error Message' THEN -3.0"
       "    ELSE NULL"
       "    END),"
       "   coalesce (new_severity,"
       "             CASE new_threat"
       "             WHEN 'Security Hole' THEN 10.0"
       "             WHEN 'Security Warning' THEN 5.0"
       "             WHEN 'Security Note' THEN 2.0"
       "             WHEN 'Log Message' THEN 0.0"
       "             WHEN 'False Positive' THEN -1.0"
       "             WHEN 'Debug Message' THEN -2.0"
       "             WHEN 'Error Message' THEN -3.0"
       "             END),"
       "   task, result, end_time"
       " FROM overrides_88;");

  sql ("INSERT INTO overrides_trash"
       " (id, uuid, owner, nvt, creation_time, modification_time, text,"
       "  hosts, port, severity, new_severity, task, result, end_time)"
       " SELECT id, uuid, owner, nvt, creation_time, modification_time, text,"
       "   hosts, port,"
       "   (CASE threat"
       "    WHEN 'Security Hole' THEN 0.1"
       "    WHEN 'Security Warning' THEN 0.1"
       "    WHEN 'Security Note' THEN 0.1"
       "    WHEN 'Alarm' THEN 0.1"
       "    WHEN 'Log Message' THEN 0.0"
       "    WHEN 'False Positive' THEN -1.0"
       "    WHEN 'Debug Message' THEN -2.0"
       "    WHEN 'Error Message' THEN -3.0"
       "    ELSE NULL"
       "    END),"
       "   coalesce (new_severity,"
       "             CASE new_threat"
       "             WHEN 'Security Hole' THEN 10.0"
       "             WHEN 'Security Warning' THEN 5.0"
       "             WHEN 'Security Note' THEN 2.0"
       "             WHEN 'Log Message' THEN 0.0"
       "             WHEN 'False Positive' THEN -1.0"
       "             WHEN 'Debug Message' THEN -2.0"
       "             WHEN 'Error Message' THEN -3.0"
       "             END),"
       "   task, result, end_time"
       " FROM overrides_trash_88;");

  /* Delete old overrides tables. */
  sql ("DROP TABLE overrides_88;");
  sql ("DROP TABLE overrides_trash_88;");

  /* Clear overridden result counts cache */
  sql ("UPDATE report_counts set override_highs = -1;");

  /* Set the database version to 89. */

  set_db_version (89);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 89 to version 90.
 *
 * @return 0 success, -1 error.
 */
int
migrate_89_to_90 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 89. */

  if (manage_db_version () != 89)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Groups, roles and users became owned by all admins. */

  sql ("UPDATE groups SET owner = NULL;");
  sql ("UPDATE roles SET owner = NULL;");
  sql ("UPDATE users SET owner = NULL;");

  /* Set the database version to 90. */

  set_db_version (90);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 90 to version 91.
 *
 * @return 0 success, -1 error.
 */
int
migrate_90_to_91 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 90. */

  if (manage_db_version () != 90)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Rename notes tables */
  sql ("ALTER TABLE notes RENAME TO notes_90;");
  sql ("ALTER TABLE notes_trash RENAME TO notes_trash_90;");

  /* Create new ones without threat and new_threat. */
  sql ("CREATE TABLE IF NOT EXISTS notes"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt,"
       "  creation_time, modification_time, text, hosts, port, severity,"
       "  task INTEGER, result INTEGER, end_time);");
  sql ("CREATE TABLE IF NOT EXISTS notes_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt,"
       "  creation_time, modification_time, text, hosts, port, severity,"
       "  task INTEGER, result INTEGER, end_time);");

  /* Migrate old notes data to new tables. */
  sql ("INSERT INTO notes"
       " (id, uuid, owner , nvt, creation_time, modification_time, text,"
       "  hosts, port, severity, task, result, end_time)"
       " SELECT id, uuid, owner, nvt, creation_time, modification_time, text,"
       "   hosts, port,"
       "   (CASE threat"
       "    WHEN 'Security Hole' THEN 0.1"
       "    WHEN 'Security Warning' THEN 0.1"
       "    WHEN 'Security Note' THEN 0.1"
       "    WHEN 'Alarm' THEN 0.1"
       "    WHEN 'Log Message' THEN 0.0"
       "    WHEN 'False Positive' THEN -1.0"
       "    WHEN 'Debug Message' THEN -2.0"
       "    WHEN 'Error Message' THEN -3.0"
       "    ELSE NULL"
       "    END),"
       "   task, result, end_time"
       " FROM notes_90;");

  sql ("INSERT INTO notes_trash"
       " (id, uuid, owner , nvt, creation_time, modification_time, text,"
       "  hosts, port, severity, task, result, end_time)"
       " SELECT id, uuid, owner, nvt, creation_time, modification_time, text,"
       "   hosts, port,"
       "   (CASE threat"
       "    WHEN 'Security Hole' THEN 0.1"
       "    WHEN 'Security Warning' THEN 0.1"
       "    WHEN 'Security Note' THEN 0.1"
       "    WHEN 'Alarm' THEN 0.1"
       "    WHEN 'Log Message' THEN 0.0"
       "    WHEN 'False Positive' THEN -1.0"
       "    WHEN 'Debug Message' THEN -2.0"
       "    WHEN 'Error Message' THEN -3.0"
       "    ELSE NULL"
       "    END),"
       "   task, result, end_time"
       " FROM notes_trash_90;");

  /* Delete old overrides tables. */
  sql ("DROP TABLE notes_90;");
  sql ("DROP TABLE notes_trash_90;");

  /* Set the database version 91. */

  set_db_version (91);

  sql ("COMMIT;");

  return 0;

}

/**
 * @brief Migrate the database from version 91 to version 92.
 *
 * @return 0 success, -1 error.
 */
int
migrate_91_to_92 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 91. */

  if (manage_db_version () != 91)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The default setting Reports Filter was renamed to Results Filter.
   * Report result filters are now of type "result".  Type "report" filters
   * are for report filters. */

  sql ("INSERT INTO settings (uuid, owner, name, comment, value)"
       " SELECT '739ab810-163d-11e3-9af6-406186ea4fc5', owner,"
       "        'Results Filter', comment, value"
       " FROM settings"
       " WHERE name = 'Reports Filter';");

  sql ("DELETE FROM settings WHERE name = 'Reports Filter';");

  sql ("UPDATE filters SET type = 'result' WHERE type = 'report';");

  /* Set the database version 92. */

  set_db_version (92);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 92 to version 93.
 *
 * @return 0 success, -1 error.
 */
int
migrate_92_to_93 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 92. */

  if (manage_db_version () != 92)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The scanner preference host_expansion was removed. */

  sql ("DELETE FROM config_preferences WHERE name = 'host_expansion';");
  sql ("DELETE FROM config_preferences_trash WHERE name = 'host_expansion';");

  /* Set the database version 93. */

  set_db_version (93);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 93 to version 94.
 *
 * @return 0 success, -1 error.
 */
int
migrate_93_to_94 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 93. */

  if (manage_db_version () != 93)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */
  /* Add column "exclude_hosts" to targets and targets_trash */
  sql ("ALTER TABLE targets ADD COLUMN exclude_hosts;");
  sql ("ALTER TABLE targets_trash ADD COLUMN exclude_hosts;");

  /* Set the database version to 94. */

  set_db_version (94);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 94 to version 95.
 *
 * @return 0 success, -1 error.
 */
int
migrate_94_to_95 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 94. */

  if (manage_db_version () != 94)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */
  /* Drop and replace the report_counts table */
  sql ("DROP TABLE report_counts;");
  sql ("CREATE TABLE IF NOT EXISTS report_counts"
       " (id INTEGER PRIMARY KEY, report INTEGER, user INTEGER,"
       "  severity, count, override);");

  /* Set the database version to 95. */

  set_db_version (95);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 95 to version 96.
 *
 * @return 0 success, -1 error.
 */
int
migrate_95_to_96 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 95. */

  if (manage_db_version () != 95)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */
  /* Add column reverse lookup columns to targets and targets_trash */
  sql ("ALTER TABLE targets ADD COLUMN reverse_lookup_only;");
  sql ("ALTER TABLE targets ADD COLUMN reverse_lookup_unify;");
  sql ("UPDATE targets SET reverse_lookup_only = 0, reverse_lookup_unify = 0;");

  sql ("ALTER TABLE targets_trash ADD COLUMN reverse_lookup_only;");
  sql ("ALTER TABLE targets_trash ADD COLUMN reverse_lookup_unify;");
  sql ("UPDATE targets_trash SET reverse_lookup_only = 0, "
       "                         reverse_lookup_unify = 0;");

  /* Set the database version to 96. */

  set_db_version (96);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 96 to version 97.
 *
 * @return 0 success, -1 error.
 */
int
migrate_96_to_97 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 96. */

  if (manage_db_version () != 96)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */
  /* Add column hosts_ordering to tasks */
  sql ("ALTER TABLE tasks ADD COLUMN hosts_ordering;");
  sql ("UPDATE tasks SET hosts_ordering = 'sequential';");

  /* Set the database version to 97. */

  set_db_version (97);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 97 to version 98.
 *
 * @return 0 success, -1 error.
 */
int
migrate_97_to_98 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 97. */

  if (manage_db_version () != 97)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */
  /* Set default value for Dynamic Severity to 0 (disabled) */
  sql ("UPDATE settings SET value = 0"
       " WHERE name = 'Dynamic Severity'"
       " AND owner IS NULL;");

  /* Set the database version to 98. */

  set_db_version (98);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 98 to version 99.
 *
 * @return 0 success, -1 error.
 */
int
migrate_98_to_99 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 98. */

  if (manage_db_version () != 98)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Remove reverse_lookup and slice_network_addresses scanner preferences. */

  sql ("DELETE FROM config_preferences WHERE name = 'reverse_lookup';");
  sql ("DELETE FROM config_preferences"
       " WHERE name = 'slice_network_addresses';");
  sql ("DELETE FROM config_preferences_trash WHERE name = 'reverse_lookup';");
  sql ("DELETE FROM config_preferences_trash"
       " WHERE name = 'slice_network_addresses';");

  /* Set the database version to 99. */

  set_db_version (99);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 99 to version 100.
 *
 * @return 0 success, -1 error.
 */
int
migrate_99_to_100 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 99. */

  if (manage_db_version () != 99)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Rename results tables */
  sql ("ALTER TABLE results RENAME TO results_99;");

  /* Create new one without subnet. */
  sql ("CREATE TABLE IF NOT EXISTS results"
       " (id INTEGER PRIMARY KEY, uuid, task INTEGER, host, port, nvt,"
       "  type, description, report, nvt_version, severity REAL)");

  /* Migrate old results data to new table. */
  sql ("INSERT INTO results"
       " (id, uuid, task, host, port, nvt, type,"
       "  description, report, nvt_version, severity)"
       " SELECT id, uuid, task, host, port, nvt, type, description, report,"
       "  nvt_version, severity FROM results_99");

  /* Delete old results table. */
  sql ("DROP TABLE results_99;");

  /* Set the database version to 100. */

  set_db_version (100);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 100 to version 101.
 *
 * @return 0 success, -1 error.
 */
int
migrate_100_to_101 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 100. */

  if (manage_db_version () != 100)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Migrate level alert condition data to severity */
  sql ("UPDATE alert_condition_data SET"
       " name = 'severity',"
       " data = CASE data"
       "        WHEN 'High' THEN 5.1"
       "        WHEN 'Medium' THEN 2.1"
       "        WHEN 'Meduim' THEN 2.1" // Fix for typo in GSA
       "        WHEN 'Low' THEN 0.1"
       "        WHEN 'Log' THEN 0.0"
       "        WHEN 'False Positive' THEN -1.0"
       "        ELSE data END"
       " WHERE name = 'level';");

  sql ("UPDATE alert_condition_data_trash SET"
       " name = 'severity',"
       " data = CASE data"
       "        WHEN 'High' THEN 5.1"
       "        WHEN 'Medium' THEN 2.1"
       "        WHEN 'Meduim' THEN 2.1" // Fix for typo in GSA
       "        WHEN 'Low' THEN 0.1"
       "        WHEN 'Log' THEN 0.0"
       "        WHEN 'False Positive' THEN -1.0"
       "        ELSE data END"
       " WHERE name = 'level';");

  /* Set the database version to 101. */

  set_db_version (101);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 101 to version 102.
 *
 * @return 0 success, -1 error.
 */
int
migrate_101_to_102 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 101. */

  if (manage_db_version () != 101)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Rename nvts tables. */
  sql ("ALTER TABLE nvts RENAME TO nvts_101;");

  /* Create new one without description column. */
  sql ("CREATE TABLE IF NOT EXISTS nvts"
       " (id INTEGER PRIMARY KEY, uuid, oid, version, name, comment, summary,"
       "  copyright, cve, bid, xref, tag, sign_key_ids,"
       "  category INTEGER, family, cvss_base, creation_time,"
       "  modification_time);");

  /* Migrate old nvts data to new table. */
  sql ("INSERT INTO nvts"
       " (id, uuid, oid, version, name, comment, summary,"
       "  copyright, cve, bid, xref, tag, sign_key_ids,"
       "  category, family, cvss_base, creation_time, modification_time)"
       " SELECT id, uuid, oid, version, name, comment, summary,"
       "  copyright, cve, bid, xref, tag, sign_key_ids,"
       "  category, family, cvss_base, creation_time, modification_time"
       "  FROM nvts_101;");

  /* Delete old nvts table. */
  sql ("DROP TABLE nvts_101;");

  /* Set the database version to 102. */

  set_db_version (102);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 102 to version 103.
 *
 * @return 0 success, -1 error.
 */
int
migrate_102_to_103 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 102. */

  if (manage_db_version () != 102)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Clear cache for affected reports */
  sql ("DELETE FROM report_counts WHERE report IN"
       " (SELECT report FROM results"
       "  WHERE severity = 'NULL' OR severity = '' OR severity IS NULL);");

  /* Add missing severity values */
  sql ("UPDATE results SET"
       " severity = CASE type"
       "            WHEN 'Error Message' THEN -3.0"
       "            WHEN 'Debug Message' THEN -2.0"
       "            WHEN 'False Positive' THEN -1.0"
       "            WHEN 'Log Message' THEN 0.0"
       "            ELSE NULL END"
       " WHERE severity = 'NULL' OR severity = '' OR severity IS NULL;");

  /* Set the database version to 103. */

  set_db_version (103);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 103 to version 104.
 *
 * @return 0 success, -1 error.
 */
int
migrate_103_to_104 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 103. */

  if (manage_db_version () != 103)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Tasks got an alterable flag. */
  sql ("ALTER TABLE tasks ADD column alterable;");
  sql ("UPDATE tasks SET alterable = 0;");

  /* Set the database version to 104. */

  set_db_version (104);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 104 to version 105.
 *
 * @return 0 success, -1 error.
 */
int
migrate_104_to_105 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 104. */

  if (manage_db_version () != 104)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Add expiration date column to reports cache. */
  sql ("ALTER TABLE report_counts ADD COLUMN end_time INTEGER;");

  /* Update cache to set expiration dates. */
  sql ("UPDATE report_counts"
       " SET end_time = (SELECT coalesce(min(end_time), 0)"
       "                 FROM overrides, results"
       "                 WHERE overrides.nvt = results.nvt"
       "                 AND results.report = report_counts.report"
       "                 AND overrides.end_time > 1)"
       " WHERE report_counts.override = 1;");

  sql ("UPDATE report_counts"
       " SET end_time = 0"
       " WHERE report_counts.override = 0;");

  /* Clear cache for reports with already expired overrides */
  sql ("DELETE FROM report_counts"
       " WHERE end_time != 0 AND end_time <= now()");

  /* Set the database version to 105. */

  set_db_version (105);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 105 to version 106.
 *
 * @return 0 success, -1 error.
 */
int
migrate_105_to_106 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 105. */

  if (manage_db_version () != 105)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  sql ("ALTER TABLE users ADD COLUMN ifaces;");
  sql ("ALTER TABLE users ADD COLUMN ifaces_allow;");
  sql ("UPDATE users SET ifaces = '', ifaces_allow = 2");

  /* Set the database version to 106. */

  set_db_version (106);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 106 to version 107.
 *
 * @return 0 success, -1 error.
 */
int
migrate_106_to_107 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 106. */

  if (manage_db_version () != 106)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Results in container tasks were being given a task of 0. */
  sql ("UPDATE results"
       " SET task = (SELECT task FROM reports WHERE reports.ROWID = report);");

  /* Set the database version to 107. */

  set_db_version (107);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 107 to version 108.
 *
 * @return 0 success, -1 error.
 */
int
migrate_107_to_108 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 107. */

  if (manage_db_version () != 107)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Change hosts and interfaces Access "Allow All" to "Deny none". */
  sql ("UPDATE users"
       " SET hosts = '', hosts_allow = 0 WHERE hosts_allow = 2;");
  sql ("UPDATE users"
       " SET ifaces = '', ifaces_allow = 0 WHERE ifaces_allow = 2;");

  /* Set the database version to 108. */

  set_db_version (108);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 108 to version 109.
 *
 * @return 0 success, -1 error.
 */
int
migrate_108_to_109 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 108. */

  if (manage_db_version () != 108)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Permission names changed to full command names. */

  sql ("UPDATE permissions SET name = 'create_' || resource_type"
       " WHERE name = 'create';");
  sql ("DELETE FROM permissions WHERE name = 'create_';");

  sql ("UPDATE permissions SET name = 'delete_' || resource_type"
       " WHERE name = 'delete';");
  sql ("DELETE FROM permissions WHERE name = 'delete_';");

  sql ("UPDATE permissions SET name = 'get_' || resource_type || 's'"
       " WHERE name = 'get';");
  sql ("DELETE FROM permissions WHERE name = 'get_';");

  sql ("UPDATE permissions SET name = 'modify_' || resource_type"
       " WHERE name = 'modify';");
  sql ("DELETE FROM permissions WHERE name = 'modify_';");

  /* Set the database version to 109. */

  set_db_version (109);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 109 to version 110.
 *
 * @return 0 success, -1 error.
 */
int
migrate_109_to_110 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 109. */

  if (manage_db_version () != 109)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The permissions tables got subject_location fields. */

  sql ("ALTER TABLE permissions ADD COLUMN subject_location;");
  sql ("UPDATE permissions SET subject_location = 0;");

  sql ("ALTER TABLE permissions_trash ADD COLUMN subject_location;");
  sql ("UPDATE permissions_trash SET subject_location = 0;");

  /* Set the database version to 110. */

  set_db_version (110);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 110 to version 111.
 *
 * @return 0 success, -1 error.
 */
int
migrate_110_to_111 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 110. */

  if (manage_db_version () != 110)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The targets tables got an alive_test field. */

  sql ("ALTER TABLE targets ADD COLUMN alive_test;");
  sql ("UPDATE targets SET alive_test = 0;");

  sql ("ALTER TABLE targets_trash ADD COLUMN alive_test;");
  sql ("UPDATE targets_trash SET alive_test = 0;");

  /* Set the database version to 111. */

  set_db_version (111);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 111 to version 112.
 *
 * @return 0 success, -1 error.
 */
int
migrate_111_to_112 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 111. */

  if (manage_db_version () != 111)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Some prefs were removed from config Host Discovery so that the NVT
   * defaults will be used instead. */

  sql ("DELETE FROM config_preferences"
       " WHERE config = (SELECT ROWID FROM configs"
       "                 WHERE uuid = '" CONFIG_UUID_HOST_DISCOVERY "')"
       " AND (name = 'Ping Host[checkbox]:Do a TCP ping'"
       "      OR name = 'Ping Host[checkbox]:Do an ICMP ping'"
       "      OR name = 'Ping Host[checkbox]:Use ARP'"
       "      OR name = 'Ping Host[checkbox]:Use nmap'"
       "      OR name = 'Ping Host[checkbox]:nmap: try also with only -sP'"
       "      OR name = 'Ping Host[entry]:nmap additional ports for -PA');");

  /* Set the database version to 112. */

  set_db_version (112);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 112 to version 113.
 *
 * @return 0 success, -1 error.
 */
int
migrate_112_to_113 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 112. */

  if (manage_db_version () != 112)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Certain levels may have been missing from the result counts cache due
   * to floating point approximation. */

  sql ("DELETE FROM report_counts;");

  /* Set the database version to 113. */

  set_db_version (113);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 113 to version 114.
 *
 * @return 0 success, -1 error.
 */
int
migrate_113_to_114 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 113. */

  if (manage_db_version () != 113)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Reports got information from scan time. */

  sql ("ALTER TABLE reports ADD COLUMN slave_uuid;");
  sql ("ALTER TABLE reports ADD COLUMN slave_name;");
  sql ("ALTER TABLE reports ADD COLUMN slave_host;");
  sql ("ALTER TABLE reports ADD COLUMN slave_port;");
  sql ("ALTER TABLE reports ADD COLUMN source_iface;");

  /* Set the database version to 114. */

  set_db_version (114);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 114 to version 115.
 *
 * @return 0 success, -1 error.
 */
int
migrate_114_to_115 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 114. */

  if (manage_db_version () != 114)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Rename nvts tables. */
  sql ("ALTER TABLE nvts RENAME TO nvts_114;");

  /* Create new one without sign_key_ids column. */
  sql ("CREATE TABLE IF NOT EXISTS nvts"
       " (id INTEGER PRIMARY KEY, uuid, oid, version, name, comment, summary,"
       "  copyright, cve, bid, xref, tag, category INTEGER, family, cvss_base,"
       "  creation_time, modification_time);");

  /* Migrate old nvts data to new table. */
  sql ("INSERT INTO nvts"
       " (id, uuid, oid, version, name, comment, summary,"
       "  copyright, cve, bid, xref, tag,"
       "  category, family, cvss_base, creation_time, modification_time)"
       " SELECT id, uuid, oid, version, name, comment, summary,"
       "  copyright, cve, bid, xref, tag,"
       "  category, family, cvss_base, creation_time, modification_time"
       "  FROM nvts_114;");

  /* Delete old nvts table. */
  sql ("DROP TABLE nvts_114;");

  /* Set the database version to 115. */

  set_db_version (115);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 115 to version 116.
 *
 * @return 0 success, -1 error.
 */
int
migrate_115_to_116 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 115. */

  if (manage_db_version () != 115)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* NVT "CPE Inventory" was removed from config "Discovery". */

  sql ("DELETE FROM nvt_selectors"
       " WHERE name = '" MANAGE_NVT_SELECTOR_UUID_DISCOVERY "'"
       " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
       " AND family_or_nvt = '1.3.6.1.4.1.25623.1.0.810002'");

  /* Set the database version to 116. */

  set_db_version (116);

  sql ("COMMIT;");

  return 0;
}

#define ID_WHEN_WITH_TRASH(type)                                 \
 " WHEN '" G_STRINGIFY (type) "' THEN"                           \
 "   COALESCE ((SELECT ROWID FROM " G_STRINGIFY (type) "s"       \
 "               WHERE uuid = attach_id),"                       \
 "             (SELECT ROWID FROM " G_STRINGIFY (type) "s_trash" \
 "               WHERE uuid = attach_id),"                       \
 "             0)"

#define ID_WHEN_WITHOUT_TRASH(type)                              \
 " WHEN '" G_STRINGIFY (type) "' THEN"                           \
 "   COALESCE ((SELECT ROWID FROM " G_STRINGIFY (type) "s"       \
 "                WHERE uuid = attach_id),"                      \
 "             0)"

#define RESOURCE_TRASH(type)                                     \
 " WHEN '" G_STRINGIFY (type) "' THEN"                           \
 "  (SELECT CASE WHEN "                                          \
 "    (EXISTS (SELECT * FROM " G_STRINGIFY (type) "s_trash"      \
 "             WHERE uuid = attach_id))"                         \
 "     THEN " G_STRINGIFY (LOCATION_TRASH)                       \
 "     ELSE " G_STRINGIFY (LOCATION_TABLE) " END)"

/**
 * @brief Migrate the database from version 116 to version 117.
 *
 * @return 0 success, -1 error.
 */
int
migrate_116_to_117 ()
{
  int scap_loaded = manage_scap_loaded ();
  int cert_loaded = manage_cert_loaded ();
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 116. */

  if (manage_db_version () != 116)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Rename attach_[...] columns in tags to resource_[...], reference
   * resources by ROWID and add new column for resource UUID. */

  sql ("ALTER TABLE tags RENAME TO tags_117;");
  sql ("ALTER TABLE tags_trash RENAME TO tags_trash_117;");

  sql ("CREATE TABLE IF NOT EXISTS tags"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
       "  creation_time, modification_time, resource_type, resource,"
       "  resource_uuid, resource_location, active, value);");

  sql ("CREATE TABLE IF NOT EXISTS groups_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  type, term, creation_time, modification_time);");

  sql ("CREATE TABLE IF NOT EXISTS roles_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");

  sql ("INSERT INTO tags"
       " (id, uuid, owner, name, comment,"
       "  creation_time, modification_time, resource_type, resource,"
       "  resource_uuid, resource_location, active, value)"
       " SELECT"
       "  ROWID, uuid, owner, name, comment, creation_time, modification_time,"
       "  attach_type,"
       "  (SELECT CASE attach_type"
       ID_WHEN_WITH_TRASH (agent)
       ID_WHEN_WITH_TRASH (alert)
       "%s" // CPE and CVE
       ID_WHEN_WITH_TRASH (config)
       "%s" // DFN_CERT_ADV
       ID_WHEN_WITH_TRASH (filter)
       ID_WHEN_WITH_TRASH (group)
       ID_WHEN_WITH_TRASH (lsc_credential)
       ID_WHEN_WITH_TRASH (note)
       ID_WHEN_WITHOUT_TRASH (nvt)
       ID_WHEN_WITH_TRASH (override)
       "%s" // OVALDEF
       ID_WHEN_WITH_TRASH (permission)
       ID_WHEN_WITH_TRASH (port_list)
       ID_WHEN_WITH_TRASH (report_format)
       ID_WHEN_WITHOUT_TRASH (report)
       ID_WHEN_WITHOUT_TRASH (result)
       ID_WHEN_WITHOUT_TRASH (role)
       ID_WHEN_WITH_TRASH (schedule)
       ID_WHEN_WITH_TRASH (slave)
       ID_WHEN_WITH_TRASH (target)
       ID_WHEN_WITHOUT_TRASH (task) // uses attribute "hidden" for trash
       ID_WHEN_WITHOUT_TRASH (user)
       "   ELSE 0 END),"
       " attach_id,"
       " (SELECT CASE attach_type"
       RESOURCE_TRASH (alert)
       RESOURCE_TRASH (config)
       RESOURCE_TRASH (filter)
       RESOURCE_TRASH (group)
       RESOURCE_TRASH (lsc_credential)
       RESOURCE_TRASH (note)
       RESOURCE_TRASH (override)
       RESOURCE_TRASH (permission)
       RESOURCE_TRASH (port_list)
       RESOURCE_TRASH (report_format)
       RESOURCE_TRASH (schedule)
       RESOURCE_TRASH (slave)
       RESOURCE_TRASH (target)
       "  WHEN 'task' THEN"
       "    COALESCE ((SELECT CASE WHEN hidden = 2 THEN "
                       G_STRINGIFY (LOCATION_TRASH)
       "               ELSE "
                       G_STRINGIFY (LOCATION_TABLE)
       "               END"
       "               FROM tasks WHERE uuid = attach_id),"
                       G_STRINGIFY (LOCATION_TABLE) ")"
       "  WHEN 'report' THEN"
       "    COALESCE ((SELECT CASE WHEN tasks.hidden = 2 THEN "
                       G_STRINGIFY (LOCATION_TRASH)
       "               ELSE "
                       G_STRINGIFY (LOCATION_TABLE)
       "               END"
       "               FROM (SELECT task FROM reports"
       "                     WHERE reports.uuid = attach_id) AS report_task"
       "               JOIN tasks ON tasks.ROWID = report_task.task),"
                       G_STRINGIFY (LOCATION_TABLE) ")"
       "  WHEN 'result' THEN"
       "    COALESCE ((SELECT CASE WHEN tasks.hidden = 2 THEN "
                       G_STRINGIFY (LOCATION_TRASH)
       "               ELSE "
                       G_STRINGIFY (LOCATION_TABLE)
       "               END"
       "               FROM (SELECT task FROM results"
       "                     WHERE results.uuid = attach_id) AS result_task"
       "               JOIN tasks ON tasks.ROWID = result_task.task),"
                       G_STRINGIFY (LOCATION_TABLE) ")"
       "  ELSE " G_STRINGIFY (LOCATION_TABLE) " END),"
       " active, value"
       " FROM tags_117;",
       scap_loaded ? ID_WHEN_WITHOUT_TRASH (cpe)
                     ID_WHEN_WITHOUT_TRASH (cve)
                   : "",
       cert_loaded ? ID_WHEN_WITHOUT_TRASH (dfn_cert_adv)
                   : "",
       scap_loaded ? ID_WHEN_WITHOUT_TRASH (ovaldef)
                   : "");

  sql ("DROP TABLE tags_117;");

  /* Rename attach_[...] columns in tags_trash to resource_[...], reference
   * resources by ROWID and add new column for resource UUID. */
  sql ("CREATE TABLE IF NOT EXISTS tags_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
       "  creation_time, modification_time, resource_type, resource,"
       "  resource_uuid, resource_location, active, value);");

  sql ("INSERT INTO tags_trash"
       " (id, uuid, owner, name, comment,"
       "  creation_time, modification_time, resource_type, resource,"
       "  resource_uuid, resource_location, active, value)"
       " SELECT"
       "  ROWID, uuid, owner, name, comment, creation_time, modification_time,"
       "  attach_type,"
       "  (SELECT CASE attach_type"
       ID_WHEN_WITH_TRASH (agent)
       ID_WHEN_WITH_TRASH (alert)
       "%s" // CPE and CVE
       ID_WHEN_WITH_TRASH (config)
       "%s" // DFN_CERT_ADV
       ID_WHEN_WITH_TRASH (filter)
       ID_WHEN_WITH_TRASH (group)
       ID_WHEN_WITH_TRASH (lsc_credential)
       ID_WHEN_WITH_TRASH (note)
       ID_WHEN_WITHOUT_TRASH (nvt)
       ID_WHEN_WITH_TRASH (override)
       "%s" // OVALDEF
       ID_WHEN_WITH_TRASH (permission)
       ID_WHEN_WITH_TRASH (port_list)
       ID_WHEN_WITH_TRASH (report_format)
       ID_WHEN_WITHOUT_TRASH (report)
       ID_WHEN_WITHOUT_TRASH (result)
       ID_WHEN_WITHOUT_TRASH (role)
       ID_WHEN_WITH_TRASH (schedule)
       ID_WHEN_WITH_TRASH (slave)
       ID_WHEN_WITH_TRASH (target)
       ID_WHEN_WITHOUT_TRASH (task) // uses attribute "hidden" for trash
       ID_WHEN_WITHOUT_TRASH (user)
       "   ELSE 0 END),"
       " attach_id,"
       " (SELECT CASE attach_type"
       RESOURCE_TRASH (alert)
       RESOURCE_TRASH (config)
       RESOURCE_TRASH (filter)
       RESOURCE_TRASH (group)
       RESOURCE_TRASH (lsc_credential)
       RESOURCE_TRASH (note)
       RESOURCE_TRASH (override)
       RESOURCE_TRASH (permission)
       RESOURCE_TRASH (port_list)
       RESOURCE_TRASH (report_format)
       RESOURCE_TRASH (schedule)
       RESOURCE_TRASH (slave)
       RESOURCE_TRASH (target)
       "  WHEN 'task' THEN"
       "    COALESCE ((SELECT CASE WHEN hidden = 2 THEN "
                       G_STRINGIFY (LOCATION_TRASH)
       "               ELSE "
                       G_STRINGIFY (LOCATION_TABLE)
       "               END"
       "               FROM tasks WHERE uuid = attach_id),"
                       G_STRINGIFY (LOCATION_TABLE) ")"
       "  WHEN 'report' THEN"
       "    COALESCE ((SELECT CASE WHEN tasks.hidden = 2 THEN "
                       G_STRINGIFY (LOCATION_TRASH)
       "               ELSE "
                       G_STRINGIFY (LOCATION_TABLE)
       "               END"
       "               FROM (SELECT task FROM reports"
       "                     WHERE reports.uuid = attach_id) AS report_task"
       "               JOIN tasks ON tasks.ROWID = report_task.task),"
                       G_STRINGIFY (LOCATION_TABLE) ")"
       "  WHEN 'result' THEN"
       "    COALESCE ((SELECT CASE WHEN tasks.hidden = 2 THEN "
                       G_STRINGIFY (LOCATION_TRASH)
       "               ELSE "
                       G_STRINGIFY (LOCATION_TABLE)
       "               END"
       "               FROM (SELECT task FROM results"
       "                     WHERE results.uuid = attach_id) AS result_task"
       "               JOIN tasks ON tasks.ROWID = result_task.task),"
                       G_STRINGIFY (LOCATION_TABLE) ")"
       "  ELSE " G_STRINGIFY (LOCATION_TABLE) " END),"
       " active, value"
       " FROM tags_trash_117;",
       scap_loaded ? ID_WHEN_WITHOUT_TRASH (cpe)
                     ID_WHEN_WITHOUT_TRASH (cve)
                   : "",
       cert_loaded ? ID_WHEN_WITHOUT_TRASH (dfn_cert_adv)
                   : "",
       scap_loaded ? ID_WHEN_WITHOUT_TRASH (ovaldef)
                   : "");

  sql ("DROP TABLE tags_trash_117;");

  /* Set the database version to 117. */

  set_db_version (117);

  sql ("COMMIT;");

  return 0;
}
#undef ID_WHEN_WITH_TRASH
#undef ID_WHEN_WITHOUT_TRASH
#undef RESOURCE_TRASH


#define RESOURCE_TRASH(type)                                     \
 " WHEN '" G_STRINGIFY (type) "' THEN"                           \
 "  (SELECT CASE WHEN "                                          \
 "    (EXISTS (SELECT * FROM " G_STRINGIFY (type) "s_trash"      \
 "             WHERE uuid = resource_uuid))"                     \
 "     THEN " G_STRINGIFY (LOCATION_TRASH)                       \
 "     ELSE " G_STRINGIFY (LOCATION_TABLE) " END)"

/**
 * @brief Migrate the database from version 117 to version 118.
 *
 * @return 0 success, -1 error.
 */
int
migrate_117_to_118 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 117. */

  if (manage_db_version () != 117)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Rebuild the resource_location column in tags and tags_trash */
  sql ("UPDATE tags SET resource_location = "
       " (SELECT CASE resource_type"
       RESOURCE_TRASH (alert)
       RESOURCE_TRASH (config)
       RESOURCE_TRASH (filter)
       RESOURCE_TRASH (group)
       RESOURCE_TRASH (lsc_credential)
       RESOURCE_TRASH (note)
       RESOURCE_TRASH (override)
       RESOURCE_TRASH (permission)
       RESOURCE_TRASH (port_list)
       RESOURCE_TRASH (report_format)
       RESOURCE_TRASH (schedule)
       RESOURCE_TRASH (slave)
       RESOURCE_TRASH (target)
       "  WHEN 'task' THEN"
       "    COALESCE ((SELECT CASE WHEN hidden = 2 THEN "
                       G_STRINGIFY (LOCATION_TRASH)
       "               ELSE "
                       G_STRINGIFY (LOCATION_TABLE)
       "               END"
       "               FROM tasks WHERE uuid = resource_uuid),"
                       G_STRINGIFY (LOCATION_TABLE) ")"
       "  WHEN 'report' THEN"
       "    COALESCE ((SELECT CASE WHEN tasks.hidden = 2 THEN "
                       G_STRINGIFY (LOCATION_TRASH)
       "               ELSE "
                       G_STRINGIFY (LOCATION_TABLE)
       "               END"
       "               FROM (SELECT task FROM reports"
       "                     WHERE reports.uuid = resource_uuid) AS report_task"
       "               JOIN tasks ON tasks.ROWID = report_task.task),"
                       G_STRINGIFY (LOCATION_TABLE) ")"
       "  WHEN 'result' THEN"
       "    COALESCE ((SELECT CASE WHEN tasks.hidden = 2 THEN "
                       G_STRINGIFY (LOCATION_TRASH)
       "               ELSE "
                       G_STRINGIFY (LOCATION_TABLE)
       "               END"
       "               FROM (SELECT task FROM results"
       "                     WHERE results.uuid = resource_uuid) AS result_task"
       "               JOIN tasks ON tasks.ROWID = result_task.task),"
                       G_STRINGIFY (LOCATION_TABLE) ")"
       "  ELSE " G_STRINGIFY (LOCATION_TABLE) " END);");

  sql ("UPDATE tags_trash SET resource_location = "
       " (SELECT CASE resource_type"
       RESOURCE_TRASH (alert)
       RESOURCE_TRASH (config)
       RESOURCE_TRASH (filter)
       RESOURCE_TRASH (group)
       RESOURCE_TRASH (lsc_credential)
       RESOURCE_TRASH (note)
       RESOURCE_TRASH (override)
       RESOURCE_TRASH (permission)
       RESOURCE_TRASH (port_list)
       RESOURCE_TRASH (report_format)
       RESOURCE_TRASH (schedule)
       RESOURCE_TRASH (slave)
       RESOURCE_TRASH (target)
       "  WHEN 'task' THEN"
       "    COALESCE ((SELECT CASE WHEN hidden = 2 THEN "
                       G_STRINGIFY (LOCATION_TRASH)
       "               ELSE "
                       G_STRINGIFY (LOCATION_TABLE)
       "               END"
       "               FROM tasks WHERE uuid = resource_uuid),"
                       G_STRINGIFY (LOCATION_TABLE) ")"
       "  WHEN 'report' THEN"
       "    COALESCE ((SELECT CASE WHEN tasks.hidden = 2 THEN "
                       G_STRINGIFY (LOCATION_TRASH)
       "               ELSE "
                       G_STRINGIFY (LOCATION_TABLE)
       "               END"
       "               FROM (SELECT task FROM reports"
       "                     WHERE reports.uuid = resource_uuid) AS report_task"
       "               JOIN tasks ON tasks.ROWID = report_task.task),"
                       G_STRINGIFY (LOCATION_TABLE) ")"
       "  WHEN 'result' THEN"
       "    COALESCE ((SELECT CASE WHEN tasks.hidden = 2 THEN "
                       G_STRINGIFY (LOCATION_TRASH)
       "               ELSE "
                       G_STRINGIFY (LOCATION_TABLE)
       "               END"
       "               FROM (SELECT task FROM results"
       "                     WHERE results.uuid = resource_uuid) AS result_task"
       "               JOIN tasks ON tasks.ROWID = result_task.task),"
                       G_STRINGIFY (LOCATION_TABLE) ")"
       "  ELSE " G_STRINGIFY (LOCATION_TABLE) " END);");

  /* Set the database version to 118. */

  set_db_version (118);

  sql ("COMMIT;");

  return 0;
}
#undef RESOURCE_TRASH

/**
 * @brief Migrate the database from version 118 to version 119.
 *
 * @return 0 success, -1 error.
 */
int
migrate_118_to_119 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 118. */

  if (manage_db_version () != 118)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Cleaning up of orphaned results was removed from startup. */

  sql ("DELETE FROM results"
       " WHERE NOT EXISTS (SELECT * FROM report_results"
       "                   WHERE report_results.result = results.id);");
  if (sqlite3_changes (task_db) > 0)
    {
      g_debug ("%s: Removed %d orphaned result(s).",
               __FUNCTION__, sqlite3_changes (task_db));
      sql ("DELETE FROM report_counts WHERE override = 0;");
      sql ("DELETE FROM report_counts WHERE override = 1;");
    }

  /* Set the database version to 119. */

  set_db_version (119);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 119 to version 120.
 *
 * @return 0 success, -1 error.
 */
int
migrate_119_to_120 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 119. */

  if (manage_db_version () != 119)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* An omission in manage_empty_trashcan was leaving permissions referring to
   * removed resources. */

  sql ("DELETE FROM permissions"
       " WHERE resource_location = " G_STRINGIFY (LOCATION_TRASH)
       " AND resource > 0"
       " AND resource_exists (resource_type, resource, resource_location) == 0;");

  sql ("DELETE FROM permissions"
       " WHERE subject_location = " G_STRINGIFY (LOCATION_TRASH)
       " AND subject > 0"
       " AND resource_exists (subject_type, subject, subject_location) == 0;");

  /* Set the database version to 120. */

  set_db_version (120);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 120 to version 121.
 *
 * @return 0 success, -1 error.
 */
int
migrate_120_to_121 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 120. */

  if (manage_db_version () != 120)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Observer role was missing the AUTHENTICATE permission. Simply delete all
   * its permissions and they will be recreated (along with AUTHENTICATE
   * permission) on start-up. */
  sql ("DELETE FROM permissions WHERE subject_type = 'role'"
       " AND subject = (SELECT ROWID FROM roles"
       "                WHERE uuid = '" ROLE_UUID_OBSERVER "');");

  /* Set the database version to 121. */

  set_db_version (121);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 121 to version 122.
 *
 * @return 0 success, -1 error.
 */
int
migrate_121_to_122 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 121. */

  if (manage_db_version () != 121)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* HELP now has a permission check, so delete User and Info roles' permissions
   * and they will be recreated (along with HELP permission) on start-up. */
  sql ("DELETE FROM permissions"
       " WHERE subject_type = 'role' AND subject IN"
       "   (SELECT ROWID FROM roles WHERE uuid = '" ROLE_UUID_USER "'"
       "    OR uuid = '" ROLE_UUID_INFO"');");

  /* Set the database version to 122. */

  set_db_version (122);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 122 to version 123.
 *
 * @return 0 success, -1 error.
 */
int
migrate_122_to_123 ()
{
  int column_found = 0;
  iterator_t column_data;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 122. */

  if (manage_db_version () != 122)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Check if targets_trash has alive_test column, which was added in the
   *  migration to version 111 but previously missing in create_tables.   */
  init_iterator (&column_data, "PRAGMA table_info (targets_trash);");
  while (next (&column_data) && column_found == 0)
    {
      const char* column_name;

      column_name = (const char*)(sqlite3_column_text (column_data.stmt, 1));
      column_found = (strcmp (column_name, "alive_test") == 0);
    }
  cleanup_iterator (&column_data);

  if (column_found == 0)
    {
      sql ("ALTER TABLE targets_trash ADD COLUMN alive_test;");
      sql ("UPDATE targets_trash SET alive_test = 0;");
    }

  /* Set the database version to 123. */

  set_db_version (123);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Array of database version migrators.
 */
static migrator_t database_migrators[]
 = {{0, NULL},
    {1, migrate_0_to_1},
    {2, migrate_1_to_2},
    {3, migrate_2_to_3},
    {4, migrate_3_to_4},
    {5, migrate_4_to_5},
    {6, migrate_5_to_6},
    {7, migrate_6_to_7},
    {8, migrate_7_to_8},
    {9, migrate_8_to_9},
    {10, migrate_9_to_10},
    {11, migrate_10_to_11},
    {12, migrate_11_to_12},
    {13, migrate_12_to_13},
    {14, migrate_13_to_14},
    {15, migrate_14_to_15},
    {16, migrate_15_to_16},
    {17, migrate_16_to_17},
    {18, migrate_17_to_18},
    {19, migrate_18_to_19},
    {20, migrate_19_to_20},
    {21, migrate_20_to_21},
    {22, migrate_21_to_22},
    {23, migrate_22_to_23},
    {24, migrate_23_to_24},
    {25, migrate_24_to_25},
    {26, migrate_25_to_26},
    {27, migrate_26_to_27},
    {28, migrate_27_to_28},
    {29, migrate_28_to_29},
    {30, migrate_29_to_30},
    {31, migrate_30_to_31},
    {32, migrate_31_to_32},
    {33, migrate_32_to_33},
    {34, migrate_33_to_34},
    {35, migrate_34_to_35},
    {36, migrate_35_to_36},
    {37, migrate_36_to_37},
    {38, migrate_37_to_38},
    {39, migrate_38_to_39},
    {40, migrate_39_to_40},
    {41, migrate_40_to_41},
    {42, migrate_41_to_42},
    {43, migrate_42_to_43},
    {44, migrate_43_to_44},
    {45, migrate_44_to_45},
    {46, migrate_45_to_46},
    {47, migrate_46_to_47},
    {48, migrate_47_to_48},
    {49, migrate_48_to_49},
    {50, migrate_49_to_50},
    {51, migrate_50_to_51},
    {52, migrate_51_to_52},
    {53, migrate_52_to_53},
    {54, migrate_53_to_54},
    {55, migrate_54_to_55},
    {56, migrate_55_to_56},
    {57, migrate_56_to_57},
    {58, migrate_57_to_58},
    {59, migrate_58_to_59},
    {60, migrate_59_to_60},
    {61, migrate_60_to_61},
    {62, migrate_61_to_62},
    {63, migrate_62_to_63},
    {64, migrate_63_to_64},
    {65, migrate_64_to_65},
    {66, migrate_65_to_66},
    {67, migrate_66_to_67},
    {68, migrate_67_to_68},
    {69, migrate_68_to_69},
    {70, migrate_69_to_70},
    {71, migrate_70_to_71},
    {72, migrate_71_to_72},
    {73, migrate_72_to_73},
    {74, migrate_73_to_74},
    {75, migrate_74_to_75},
    {76, migrate_75_to_76},
    {77, migrate_76_to_77},
    {78, migrate_77_to_78},
    {79, migrate_78_to_79},
    {80, migrate_79_to_80},
    {81, migrate_80_to_81},
    {82, migrate_81_to_82},
    {83, migrate_82_to_83},
    {84, migrate_83_to_84},
    {85, migrate_84_to_85},
    {86, migrate_85_to_86},
    {87, migrate_86_to_87},
    {88, migrate_87_to_88},
    {89, migrate_88_to_89},
    {90, migrate_89_to_90},
    {91, migrate_90_to_91},
    {92, migrate_91_to_92},
    {93, migrate_92_to_93},
    {94, migrate_93_to_94},
    {95, migrate_94_to_95},
    {96, migrate_95_to_96},
    {97, migrate_96_to_97},
    {98, migrate_97_to_98},
    {99, migrate_98_to_99},
    {100, migrate_99_to_100},
    {101, migrate_100_to_101},
    {102, migrate_101_to_102},
    {103, migrate_102_to_103},
    {104, migrate_103_to_104},
    {105, migrate_104_to_105},
    {106, migrate_105_to_106},
    {107, migrate_106_to_107},
    {108, migrate_107_to_108},
    {109, migrate_108_to_109},
    {110, migrate_109_to_110},
    {111, migrate_110_to_111},
    {112, migrate_111_to_112},
    {113, migrate_112_to_113},
    {114, migrate_113_to_114},
    {115, migrate_114_to_115},
    {116, migrate_115_to_116},
    {117, migrate_116_to_117},
    {118, migrate_117_to_118},
    {119, migrate_118_to_119},
    {120, migrate_119_to_120},
    {121, migrate_120_to_121},
    {122, migrate_121_to_122},
    {123, migrate_122_to_123},
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
  g_log_set_handler (G_LOG_DOMAIN,
                     ALL_LOG_LEVELS,
                     (GLogFunc) openvas_log_func,
                     log_config);
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
int
migrate_is_available (int old_version, int new_version)
{
  migrator_t *migrators;

  migrators = database_migrators + old_version + 1;

  while ((migrators->version >= 0) && (migrators->version <= new_version))
    {
      if (migrators->function == NULL) return 0;
      if (migrators->version == new_version) return 1;
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

  g_log_set_handler (G_LOG_DOMAIN,
                     ALL_LOG_LEVELS,
                     (GLogFunc) openvas_log_func,
                     log_config);

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
      g_warning ("%s: no task tables yet, run a --rebuild to create them.\n",
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
          case  0:
            cleanup_manage_process (TRUE);
            return  2;
        }

      /* Call the migrators to take the DB from the old version to the new. */

      migrators = database_migrators + old_version + 1;

      while ((migrators->version >= 0) && (migrators->version <= new_version))
        {
          if (migrators->function == NULL)
            {
              cleanup_manage_process (TRUE);
              return -1;
            }

          infof ("   Migrating to %i", migrators->version);

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
      switch (openvas_migrate_secinfo (SBINDIR "/openvas-scapdata-sync",
                                       SCAP_FEED))
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
      switch (openvas_migrate_secinfo (SBINDIR "/openvas-certdata-sync",
                                       CERT_FEED))
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
