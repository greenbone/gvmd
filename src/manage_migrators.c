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

/**
 * @brief Gets or creates a tls_certificate_location in the version 213 format.
 *
 * If a location with matching host_ip and port exists its id is returned,
 *  otherwise a new one is created and its id is returned.
 *
 * @param[in]  host_ip  IP address of the location
 * @param[in]  port     Port number of the location
 *
 * @return Row id of the tls_certificate_location
 */
resource_t
tls_certificate_get_location_213 (const char *host_ip,
                                  const char *port)
{
  resource_t location = 0;
  char *quoted_host_ip, *quoted_port;
  quoted_host_ip = host_ip ? sql_quote (host_ip) : g_strdup ("");
  quoted_port = port ? sql_quote (port) : g_strdup ("");

  sql_int64 (&location,
             "SELECT id"
             " FROM tls_certificate_locations"
             " WHERE host_ip = '%s'"
             "   AND port = '%s'",
             quoted_host_ip,
             quoted_port);

  if (location)
    {
      g_free (quoted_host_ip);
      g_free (quoted_port);
      return location;
    }

  sql ("INSERT INTO tls_certificate_locations"
       "  (uuid, host_ip, port)"
       " VALUES (make_uuid (), '%s', '%s')",
       quoted_host_ip,
       quoted_port);

  location = sql_last_insert_id ();

  g_free (quoted_host_ip);
  g_free (quoted_port);

  return location;
}

/**
 * @brief Gets or creates a tls_certificate_origin in the version 213 format.
 *
 * If an origin with matching type, id and data exists its id is returned,
 *  otherwise a new one is created and its id is returned.
 *
 * @param[in]  origin_type  Origin type, e.g. "GMP" or "Report"
 * @param[in]  origin_id    Origin resource id, e.g. a report UUID.
 * @param[in]  origin_data  Origin extra data, e.g. OID of generating NVT.
 *
 * @return Row id of the tls_certificate_origin
 */
resource_t
tls_certificate_get_origin_213 (const char *origin_type,
                                const char *origin_id,
                                const char *origin_data)
{
  resource_t origin = 0;
  char *quoted_origin_type, *quoted_origin_id, *quoted_origin_data;
  quoted_origin_type = origin_type ? sql_quote (origin_type) : g_strdup ("");
  quoted_origin_id = origin_id ? sql_quote (origin_id) : g_strdup ("");
  quoted_origin_data = origin_data ? sql_quote (origin_data) : g_strdup ("");

  sql_int64 (&origin,
             "SELECT id"
             " FROM tls_certificate_origins"
             " WHERE origin_type = '%s'"
             "   AND origin_id = '%s'"
             "   AND origin_data = '%s'",
             quoted_origin_type,
             quoted_origin_id,
             quoted_origin_data);

  if (origin)
    {
      g_free (quoted_origin_type);
      g_free (quoted_origin_id);
      g_free (quoted_origin_data);
      return origin;
    }

  sql ("INSERT INTO tls_certificate_origins"
       "  (uuid, origin_type, origin_id, origin_data)"
       " VALUES (make_uuid (), '%s', '%s', '%s')",
       quoted_origin_type,
       quoted_origin_id,
       quoted_origin_data);

  origin = sql_last_insert_id ();

  g_free (quoted_origin_type);
  g_free (quoted_origin_id);
  g_free (quoted_origin_data);

  return origin;
}

/**
 * @brief Migrate the database from version 212 to version 213.
 *
 * @return 0 success, -1 error.
 */
int
migrate_212_to_213 ()
{
  iterator_t tls_certs;
  resource_t import_origin;

  gchar *sha256_fingerprint, *serial;

  sha256_fingerprint = NULL;
  serial = NULL;

  sql_begin_immediate ();

  /* Ensure that the database is currently version 212. */

  if (manage_db_version () != 212)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Add columns to tls_certificates */
  sql ("ALTER TABLE tls_certificates"
       " ADD COLUMN sha256_fingerprint text;");
  sql ("ALTER TABLE tls_certificates"
       " ADD COLUMN serial text;");

  /* Change type of timestamp columns because some expiration times
   *  may exceed the limits of 32 bit integers
   */
  sql ("ALTER TABLE tls_certificates"
       " ALTER COLUMN activation_time TYPE bigint");
  sql ("ALTER TABLE tls_certificates"
       " ALTER COLUMN expiration_time TYPE bigint");
  sql ("ALTER TABLE tls_certificates"
       " ALTER COLUMN creation_time TYPE bigint");
  sql ("ALTER TABLE tls_certificates"
       " ALTER COLUMN modification_time TYPE bigint");

  /* Create new tables */
  sql ("CREATE TABLE tls_certificate_locations"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  host_ip text,"
       "  port text);");

  sql ("CREATE INDEX tls_certificate_locations_by_host_ip"
       " ON tls_certificate_locations (host_ip)");

  sql ("CREATE TABLE tls_certificate_origins"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  origin_type text,"
       "  origin_id text,"
       "  origin_data text);");

  sql ("CREATE INDEX tls_certificate_origins_by_origin_id_and_type"
       " ON tls_certificate_origins (origin_id, origin_type)");

  sql ("CREATE TABLE tls_certificate_sources"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  tls_certificate integer REFERENCES tls_certificates (id),"
       "  location integer REFERENCES tls_certificate_locations (id),"
       "  origin integer REFERENCES tls_certificate_origins (id),"
       "  timestamp bigint,"
       "  tls_versions text);");

  /* Remove now unused tls_certificates_trash table */
  sql ("DROP TABLE IF EXISTS tls_certificates_trash;");

  /* Add origin and source for manual GMP import */
  sql ("INSERT INTO tls_certificate_origins"
       " (uuid, origin_type, origin_id, origin_data)"
       " VALUES (make_uuid(), 'Import', '', '')");
  import_origin = sql_last_insert_id ();

  /* Set the sha256_fingerprint and serial for existing tls_certificates */
  init_iterator (&tls_certs,
                 "SELECT id, certificate, creation_time"
                 " FROM tls_certificates");
  while (next (&tls_certs))
    {
      tls_certificate_t tls_certificate;
      const char *certificate_64;
      gsize certificate_size;
      unsigned char *certificate;
      time_t creation_time;

      tls_certificate = iterator_int64 (&tls_certs, 0);
      certificate_64 = iterator_string (&tls_certs, 1);
      certificate = g_base64_decode (certificate_64, &certificate_size);
      creation_time = iterator_int64 (&tls_certs, 2);

      get_certificate_info ((gchar*)certificate, 
                            certificate_size,
                            NULL,   /* activation_time */
                            NULL,   /* expiration_time */
                            NULL,   /* md5_fingerprint */
                            &sha256_fingerprint,
                            NULL,   /* subject */
                            NULL,   /* issuer */
                            &serial,
                            NULL);  /* certificate_format */

      sql ("UPDATE tls_certificates"
           " SET sha256_fingerprint = '%s', serial = '%s'"
           " WHERE id = %llu",
           sha256_fingerprint,
           serial,
           tls_certificate);

      sql ("INSERT INTO tls_certificate_sources"
           " (uuid, tls_certificate, origin, location, timestamp)"
           " VALUES (make_uuid(), %llu, %llu, NULL, %ld);",
           tls_certificate,
           import_origin,
           creation_time);

      g_free (sha256_fingerprint);
    }
  cleanup_iterator (&tls_certs);

  /* Set the database version to 213 */

  set_db_version (213);

  sql_commit ();

  return 0;
}

#undef UPDATE_DASHBOARD_SETTINGS

/**
 * @brief The oldest version for which migration is supported
 */
#define MIGRATE_MIN_OLD_VERSION 205

/**
 * @brief Array of database version migrators.
 */
static migrator_t database_migrators[] = {
  {206, migrate_205_to_206},
  {207, migrate_206_to_207},
  {208, migrate_207_to_208},
  {209, migrate_208_to_209},
  {210, migrate_209_to_210},
  {211, migrate_210_to_211},
  {212, migrate_211_to_212},
  {213, migrate_212_to_213},
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
