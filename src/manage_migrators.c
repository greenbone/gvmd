/* Copyright (C) 2013-2021 Greenbone Networks GmbH
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
#include "manage_migrators_219_to_220_names.h"
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

  /* Ensure the table tls_certificates exists */
  sql ("CREATE TABLE IF NOT EXISTS tls_certificates"
       " (id SERIAL PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer REFERENCES users (id) ON DELETE RESTRICT,"
       "  name text,"
       "  comment text,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  certificate text,"
       "  subject_dn text,"
       "  issuer_dn text,"
       "  activation_time integer,"
       "  expiration_time integer,"
       "  md5_fingerprint text,"
       "  trust integer,"
       "  certificate_format text);");

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

/**
 * @brief Create a TLS certificate in the version 214 format.
 *
 * @param[in]  owner              Owner of the new tls_certificate.
 * @param[in]  certificate_b64    The Base64 encoded certificate.
 * @param[in]  subject_dn         The subject DN of the certificate.
 * @param[in]  issuer_dn          The issuer DN of the certificate.
 * @param[in]  activation_time    Time before which the certificate is invalid.
 * @param[in]  expiration_time    Time after which the certificate is expired.
 * @param[in]  md5_fingerprint    MD5 fingerprint of the certificate.
 * @param[in]  sha256_fingerprint SHA-256 fingerprint of the certificate.
 * @param[in]  serial             Serial of the certificate.
 * @param[in]  certificate_format Certificate format (DER or PEM).
 *
 * @return The new TLS certificate.
 */
static tls_certificate_t
make_tls_certificate_214 (user_t owner,
                          const char *certificate_b64,
                          const char *subject_dn,
                          const char *issuer_dn,
                          time_t activation_time,
                          time_t expiration_time,
                          const char *md5_fingerprint,
                          const char *sha256_fingerprint,
                          const char *serial,
                          gnutls_x509_crt_fmt_t certificate_format)
{
  gchar *quoted_certificate_b64, *quoted_subject_dn, *quoted_issuer_dn;
  gchar *quoted_md5_fingerprint, *quoted_sha256_fingerprint, *quoted_serial;
  tls_certificate_t ret;

  quoted_certificate_b64
    = certificate_b64 ? sql_quote (certificate_b64) : NULL;
  quoted_subject_dn
    = subject_dn ? sql_ascii_escape_and_quote (subject_dn) : NULL;
  quoted_issuer_dn
    = issuer_dn ? sql_ascii_escape_and_quote (issuer_dn) : NULL;
  quoted_md5_fingerprint
    = md5_fingerprint ? sql_quote (md5_fingerprint) : NULL;
  quoted_sha256_fingerprint
    = sha256_fingerprint ? sql_quote (sha256_fingerprint) : NULL;
  quoted_serial
    = serial ? sql_quote (serial) : NULL;

  sql ("INSERT INTO tls_certificates"
       " (uuid, owner,"
       "  name, comment, creation_time, modification_time,"
       "  certificate, subject_dn, issuer_dn, trust,"
       "  activation_time, expiration_time,"
       "  md5_fingerprint, sha256_fingerprint, serial, certificate_format)"
       " SELECT make_uuid(), %llu,"
       "        '%s', '%s', m_now(), m_now(),"
       "        '%s', '%s', '%s', %d,"
       "        %ld, %ld,"
       "        '%s', '%s', '%s', '%s';",
       owner,
       sha256_fingerprint ? quoted_sha256_fingerprint : "",
       "", /* comment */
       certificate_b64 ? quoted_certificate_b64 : "",
       subject_dn ? quoted_subject_dn : "",
       issuer_dn ? quoted_issuer_dn : "",
       0, /* trust */
       activation_time,
       expiration_time,
       md5_fingerprint ? quoted_md5_fingerprint : "",
       sha256_fingerprint ? quoted_sha256_fingerprint : "",
       serial ? quoted_serial : "",
       tls_certificate_format_str (certificate_format));

  ret = sql_last_insert_id ();

  g_free (quoted_certificate_b64);
  g_free (quoted_subject_dn);
  g_free (quoted_issuer_dn);
  g_free (quoted_md5_fingerprint);
  g_free (quoted_sha256_fingerprint);
  g_free (quoted_serial);

  return ret;
}

/**
 * @brief Create temporary, indexed tables for TLS certificate host details.
 *
 * This makes it quicker to access host details that are slow to get repeatedly
 * for every TLS certificate, presumably because of the "LIKE" conditions
 * for the name or value field.
 */
static void
create_temp_tables_213_to_214 ()
{
  // "SSLInfo", selected by a fingerprint in the value
  sql ("CREATE TEMP TABLE report_host_details_sslinfo"
        " (report_host integer,"
        "  value text,"
        "  fingerprint text,"
        "  port text);");
  sql ("INSERT INTO report_host_details_sslinfo"
        "               (report_host, value, fingerprint, port)"
        " SELECT report_host,"
        "        value,"
        "        (regexp_matches(value, '(.*):.*:(.*)'))[2] AS fingerprint,"
        "        (regexp_matches(value, '(.*):.*:(.*)'))[1] AS port"
        "  FROM report_host_details WHERE name = 'SSLInfo';");
  sql ("CREATE INDEX"
       " ON report_host_details_sslinfo (report_host, fingerprint)");

  // "TLS/...", selected by a port number in the name
  sql ("CREATE TEMP TABLE report_host_details_tls_ports"
       "  (report_host integer,"
       "   port text,"
       "   value text)");
  sql ("INSERT INTO report_host_details_tls_ports"
       "              (report_host, port, value)"
       " SELECT report_host,"
       "        substring (name, 5) AS port,"
       "        value"
       "  FROM report_host_details"
       "  WHERE name LIKE 'TLS/%%' AND name != 'TLS/port';");
  sql ("CREATE INDEX"
        " ON report_host_details_tls_ports (report_host)");

  // "SSLDetails:...", selected by a fingerprint in the name
  sql ("CREATE TEMP TABLE report_host_details_ssldetails"
       "  (report_host integer,"
       "   fingerprint text,"
       "   value text,"
       "   start_time integer)");
  sql ("INSERT INTO report_host_details_ssldetails"
       "              (report_host, fingerprint, value, start_time)"
       " SELECT report_host,"
       "        substring (name, 12) AS fingerprint,"
       "        rhd.value,"
       "        report_hosts.start_time"
       "  FROM report_host_details AS rhd"
       "  JOIN report_hosts"
       "    ON report_hosts.id = rhd.report_host"
       "  WHERE name LIKE 'SSLDetails:%%';");
  sql ("CREATE INDEX"
        " ON report_host_details_ssldetails (report_host, fingerprint)");
}

/**
 * @brief Migrate the database from version 213 to version 214.
 *
 * @return 0 success, -1 error.
 */
int
migrate_213_to_214 ()
{
  iterator_t tls_certs;
  char *previous_fpr;
  user_t previous_owner;
  tls_certificate_t current_tls_certificate;

  time_t activation_time, expiration_time;
  gchar *md5_fingerprint, *sha256_fingerprint, *subject, *issuer, *serial;
  gnutls_x509_crt_fmt_t certificate_format;

  previous_fpr = NULL;
  previous_owner = 0;
  current_tls_certificate = 0;

  activation_time = -1;
  expiration_time = -1;
  md5_fingerprint = NULL;
  sha256_fingerprint = NULL;
  subject = NULL;
  issuer = NULL;
  serial = NULL;
  certificate_format = 0;

  sql_begin_immediate ();

  /* Ensure that the database is currently version 213. */

  if (manage_db_version () != 213)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Collect TLS certificates from host details
   *
   * The outer loop collects the details containing the
   *  Base64 encoded certificates and their SHA-256 fingerprints
   *  in an order that reduces how often the data has to extracted or
   *  queried from other host details:
   *
   * - The detail name containing the fingerprint is first, to reduce the
   *    number of times the certificate info must be fetched.
   * - The owner is second so each certificate is created only once per user
   *    without checking if it was already created in different report or not.
   * - The report id is last so tls_certificate_sources are created in the
   *   same order as the reports.
   */
  create_temp_tables_213_to_214 ();

  init_iterator (&tls_certs,
                 "SELECT rhd.value, rhd.name, reports.owner, rhd.report_host,"
                 "       report_hosts.host, reports.uuid, rhd.source_name,"
                 "       coalesce (report_hosts.start_time, reports.date)"
                 " FROM report_host_details AS rhd"
                 " JOIN report_hosts ON rhd.report_host = report_hosts.id"
                 " JOIN reports ON report_hosts.report = reports.id"
                 " WHERE source_description = 'SSL/TLS Certificate'"
                 "    OR source_description = 'SSL Certificate'"
                 " ORDER BY rhd.name, reports.owner, reports.id");

  while (next (&tls_certs))
    {
      const char *certificate_prefixed, *certificate_b64;
      gsize certificate_size;
      unsigned char *certificate;
      const char *scanner_fpr_prefixed, *scanner_fpr;
      gchar *quoted_scanner_fpr;
      user_t owner;
      resource_t report_host;
      const char *host_ip, *report_id, *source_name;
      time_t timestamp;

      iterator_t ports;
      gboolean has_ports;
      gchar *quoted_source_name;

      certificate_prefixed = iterator_string (&tls_certs, 0);
      certificate_b64 = g_strrstr (certificate_prefixed, ":") + 1;

      certificate = g_base64_decode (certificate_b64, &certificate_size);

      scanner_fpr_prefixed = iterator_string (&tls_certs, 1);
      scanner_fpr = g_strrstr (scanner_fpr_prefixed, ":") + 1;

      quoted_scanner_fpr = sql_quote (scanner_fpr);

      owner = iterator_int64 (&tls_certs, 2);
      report_host = iterator_int64 (&tls_certs, 3);
      host_ip = iterator_string (&tls_certs, 4);
      report_id = iterator_string (&tls_certs, 5);
      source_name = iterator_string (&tls_certs, 6);
      timestamp = iterator_int64 (&tls_certs, 7);

      quoted_source_name = sql_quote (source_name);

      // Get certificate data only once per fingerprint
      if (previous_fpr == NULL
          || strcmp (previous_fpr, quoted_scanner_fpr))
        {
          char *ssldetails;

          activation_time = -1;
          expiration_time = -1;
          g_free (md5_fingerprint);
          md5_fingerprint = NULL;
          g_free (sha256_fingerprint);
          sha256_fingerprint = NULL;
          g_free (subject);
          subject = NULL;
          g_free (issuer);
          issuer = NULL;
          g_free (serial);
          serial = NULL;
          certificate_format = 0;

          /* Try extracting the data directly from the certificate */
          get_certificate_info ((gchar*)certificate,
                                certificate_size,
                                &activation_time,
                                &expiration_time,
                                &md5_fingerprint,
                                &sha256_fingerprint,
                                &subject,
                                &issuer,
                                &serial,
                                &certificate_format);

          /* Use fingerprint from host detail
           *  in case get_certificate_info fails */
          if (sha256_fingerprint == NULL)
            sha256_fingerprint = g_strdup (scanner_fpr);

          /* Also use SSLDetails in case get_certificate_info fails
           *  or to ensure consistency with the host details */
          ssldetails
            = sql_string ("SELECT value"
                          " FROM report_host_details_ssldetails"
                          " WHERE fingerprint = '%s'"
                          " ORDER BY start_time DESC"
                          " LIMIT 1;",
                          quoted_scanner_fpr);

          if (ssldetails)
            parse_ssldetails (ssldetails,
                              &activation_time,
                              &expiration_time,
                              &issuer,
                              &serial);
          else
            g_warning ("%s: No SSLDetails found for fingerprint %s",
                       __func__,
                       scanner_fpr);

          free (ssldetails);
        }

      /* Ordering should ensure the certificate is unique for each owner */
      if (owner != previous_owner
          || previous_fpr == NULL
          || strcmp (previous_fpr, quoted_scanner_fpr))
        {
          current_tls_certificate = 0;
          sql_int64 (&current_tls_certificate,
                     "SELECT id FROM tls_certificates"
                     " WHERE sha256_fingerprint = '%s'"
                     "   AND owner = %llu",
                     quoted_scanner_fpr, owner);

          if (current_tls_certificate == 0)
            {
              current_tls_certificate
                = make_tls_certificate_214 (owner,
                                            certificate_b64,
                                            subject,
                                            issuer,
                                            activation_time,
                                            expiration_time,
                                            md5_fingerprint,
                                            sha256_fingerprint,
                                            serial,
                                            certificate_format);
            }
        }

      /* Collect ports for each unique certificate and owner */
      init_iterator (&ports,
                     "SELECT port FROM report_host_details_sslinfo"
                     " WHERE report_host = %llu"
                     "   AND fingerprint = '%s'",
                     report_host,
                     quoted_scanner_fpr);

      has_ports = FALSE;
      while (next (&ports))
        {
          const char *port;
          gchar *quoted_port;
          GString *versions;
          iterator_t versions_iter;
          resource_t cert_location, cert_origin;

          port = iterator_string (&ports, 0);
          quoted_port = sql_quote (port);

          has_ports = TRUE;

          /* Collect TLS versions for each port */
          versions = g_string_new ("");
          init_iterator (&versions_iter,
                         "SELECT value FROM report_host_details_tls_ports"
                         " WHERE report_host = %llu"
                         "   AND port = '%s'",
                         report_host,
                         quoted_port);
          while (next (&versions_iter))
            {
              gchar *quoted_version;
              quoted_version = sql_quote (iterator_string (&versions_iter, 0));

              if (versions->len)
                g_string_append (versions, ", ");
              g_string_append (versions, quoted_version);
            }
          cleanup_iterator (&versions_iter);

          cert_location
            = tls_certificate_get_location_213 (host_ip, port);
          cert_origin
            = tls_certificate_get_origin_213 ("Report",
                                              report_id,
                                              quoted_source_name);

          sql ("INSERT INTO tls_certificate_sources"
               " (uuid, tls_certificate, location, origin,"
               "  timestamp, tls_versions)"
               " VALUES (make_uuid (), %llu, %llu, %llu,"
               "         %ld, '%s')",
               current_tls_certificate,
               cert_location,
               cert_origin,
               timestamp,
               versions->str);

          g_free (quoted_port);
          g_string_free (versions, TRUE);
        }

      if (has_ports == FALSE)
        g_warning ("Certificate without ports: %s report:%s host:%s",
                   quoted_scanner_fpr, report_id, host_ip);

      cleanup_iterator (&ports);

      g_free (quoted_source_name);

      g_free (previous_fpr);
      previous_fpr = quoted_scanner_fpr;
      previous_owner = owner;
    }
  cleanup_iterator (&tls_certs);

  sql ("DROP TABLE report_host_details_sslinfo;");
  sql ("DROP TABLE report_host_details_tls_ports;");
  sql ("DROP TABLE report_host_details_ssldetails;");

  /* Set the database version to 214 */

  set_db_version (214);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 214 to version 215.
 *
 * @return 0 success, -1 error.
 */
int
migrate_214_to_215 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 214. */

  if (manage_db_version () != 214)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The column nbefile was removed from reports. */
  sql ("ALTER TABLE reports DROP COLUMN nbefile;");

  /* Set the database version to 215 */

  set_db_version (215);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 215 to version 216.
 *
 * @return 0 success, -1 error.
 */
int
migrate_215_to_216 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 215. */

  if (manage_db_version () != 215)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Extend table "nvts" with additional column "solution" */
  sql ("ALTER TABLE IF EXISTS nvts ADD COLUMN solution text;");

  /* Set the database version to 216. */

  set_db_version (216);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 216 to version 217.
 *
 * @return 0 success, -1 error.
 */
int
migrate_216_to_217 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 216. */

  if (manage_db_version () != 216)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Ticket references to reports and results are now cleared when the
   * report is deleted. */

  sql ("UPDATE tickets"
       " SET report = -1"
       " WHERE report NOT IN (SELECT id FROM reports);");

  sql ("UPDATE ticket_results"
       " SET report = -1, result = -1"
       " WHERE report NOT IN (SELECT id FROM reports);");

  /* Set the database version to 217. */

  set_db_version (217);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 217 to version 218.
 *
 * @return 0 success, -1 error.
 */
int
migrate_217_to_218 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 217. */

  if (manage_db_version () != 217)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Ensure all user names are unique */

  sql ("UPDATE users"
       " SET name = uniquify('user', name, NULL, '')"
       " WHERE id != (SELECT min(id) FROM users AS inner_users"
       "              WHERE users.name = inner_users.name);");

  /* Add an UNIQUE constraint to the name column of users */

  sql ("ALTER TABLE users ADD UNIQUE (name);");

  /* Set the database version to 218. */

  set_db_version (218);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 218 to version 219.
 *
 * @return 0 success, -1 error.
 */
int
migrate_218_to_219 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 218. */

  if (manage_db_version () != 218)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Extend table "nvts" with additional columns "summary",
   * "insight", "affected", "detection" and "impact" */
  sql ("ALTER TABLE IF EXISTS nvts ADD COLUMN summary text;");
  sql ("ALTER TABLE IF EXISTS nvts ADD COLUMN insight text;");
  sql ("ALTER TABLE IF EXISTS nvts ADD COLUMN affected text;");
  sql ("ALTER TABLE IF EXISTS nvts ADD COLUMN detection text;");
  sql ("ALTER TABLE IF EXISTS nvts ADD COLUMN impact text;");

  /* Set the database version to 219. */

  set_db_version (219);

  sql_commit ();

  return 0;
}

/**
 * @brief Get new name of a preference.
 *
 * @param[in]  old_name  Old name of preference.
 *
 * @return Static string containing new name for preference if found, else NULL.
 */
static const gchar *
migrate_219_to_220_new_name (const char *old_name)
{
  int index;

  for (index = 0; migrate_219_to_220_names[index][0]; index++)
    if (strcmp (migrate_219_to_220_names[index][0], old_name) == 0)
      return migrate_219_to_220_names[index][1];
  return NULL;
}

/**
 * @brief Converts old NVT preferences to the new format.
 *
 * @param[in]  table_name  The name of the table to update.
 */
static void
replace_preference_names_219_to_220 (const char *table_name)
{
  iterator_t preferences;

  /* 1.3.6.1.4.1.25623.1.0.14259:checkbox:Log nmap output
   * =>
   * 1.3.6.1.4.1.25623.1.0.14259:21:checkbox:Log nmap output */

  init_iterator (&preferences,
                 "SELECT id, name"
                 " FROM \"%s\""
                 " WHERE name LIKE '%%:%%:%%'"
                 " AND name !~ '.*:[0-9]+:.*:.*';",
                 table_name);

  while (next (&preferences))
    {
      resource_t preference;
      const char *old_name;
      const gchar *new_name;

      preference = iterator_int64 (&preferences, 0);
      old_name = iterator_string (&preferences, 1);
      new_name = migrate_219_to_220_new_name (old_name);
      if (new_name)
        {
          gchar *quoted_new_name;

          quoted_new_name = sql_quote (new_name);
          sql ("UPDATE \"%s\" SET name = '%s' WHERE id = %llu;",
               table_name,
               quoted_new_name,
               preference);
          g_free (quoted_new_name);
        }
      else
        g_warning ("%s: No new name for '%s'", __func__, old_name);
    }
  cleanup_iterator (&preferences);
}

/**
 * @brief Migrate the database from version 219 to version 220.
 *
 * @return 0 success, -1 error.
 */
int
migrate_219_to_220 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 219. */

  if (manage_db_version () != 219)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* OSP uses lowercase for timeout NVT preferences where OTP used a capital,
   * so update those first:
   *
   *     1.3.6.1.4.1.25623.1.0.107305:entry:Timeout
   *     =>
   *     1.3.6.1.4.1.25623.1.0.107305:entry:timeout  */

  sql ("UPDATE nvt_preferences"
       " SET name = split_part (name, ':', 1) || ':entry:timeout'"
       " WHERE name = split_part (name, ':', 1) || ':entry:Timeout';");

  /* Then update config and NVT preferences from the 3 part format to the
   * newer 4 part format:
   *
   *     1.3.6.1.4.1.25623.1.0.14259:checkbox:Log nmap output
   *     =>
   *     1.3.6.1.4.1.25623.1.0.14259:21:checkbox:Log nmap output
   *
   * Any preferences that aren't in our hardcoded list will be updated after
   * the first NVT sync. */

  replace_preference_names_219_to_220 ("nvt_preferences");
  replace_preference_names_219_to_220 ("config_preferences");
  replace_preference_names_219_to_220 ("config_preferences_trash");

  /* Force an NVT update to update newer NVTs not covered by the
   *  hardcoded list in case the feed update was run just before migration. */
  sql ("UPDATE meta SET value='0' WHERE name='nvts_feed_version';");

  /* Set the database version to 220. */

  set_db_version (220);

  sql_commit ();

  return 0;
}

/**
 * @brief Convert iCalendar strings of schedules to new format for version 221.
 *
 * @param[in]  trash  Whether to convert the trash table.
 */
static void
convert_schedules_221 (gboolean trash)
{
  iterator_t schedules;

  init_iterator (&schedules,
                 "SELECT id, icalendar, uuid FROM %s;",
                 trash ? "schedules_trash" : "schedules");

  while (next (&schedules))
    {
      schedule_t schedule;
      const char *ical_string, *schedule_id;
      icalcomponent *ical_component;
      gchar *error_out;

      error_out = NULL;
      schedule = iterator_int64 (&schedules, 0);
      ical_string = iterator_string (&schedules, 1);
      schedule_id = iterator_string (&schedules, 2);

      ical_component = icalendar_from_string (ical_string,
                                              icaltimezone_get_utc_timezone (),
                                              &error_out);
      if (ical_component == NULL)
        g_warning ("Error converting schedule %s: %s", schedule_id, error_out);
      else
        {
          gchar *quoted_ical;

          quoted_ical
            = sql_quote (icalcomponent_as_ical_string (ical_component));

          sql ("UPDATE %s SET icalendar = '%s' WHERE id = %llu",
               trash ? "schedules_trash" : "schedules",
               quoted_ical,
               schedule);

          g_free (quoted_ical);
        }

      g_free (error_out);
    }

  cleanup_iterator (&schedules);
}

/**
 * @brief Migrate the database from version 220 to version 221.
 *
 * @return 0 success, -1 error.
 */
int
migrate_220_to_221 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 220. */

  if (manage_db_version () != 220)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Convert iCalendar strings of all schedules */
  convert_schedules_221 (FALSE);
  convert_schedules_221 (TRUE);

  /* Set the database version to 221. */

  set_db_version (221);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 221 to version 222.
 *
 * @return 0 success, -1 error.
 */
int
migrate_221_to_222 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 221. */

  if (manage_db_version () != 221)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Remove permissions on the remove command MODIFY_REPORT */
  sql ("DELETE FROM permissions WHERE name = 'modify_report';");
  sql ("DELETE FROM permissions_trash WHERE name = 'modify_report';");

  /* Set the database version to 222. */

  set_db_version (222);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 222 to version 223.
 *
 * @return 0 success, -1 error.
 */
int
migrate_222_to_223 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 222. */

  if (manage_db_version () != 222)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Extend table "nvts" with additional column "solution_method" */
  sql ("ALTER TABLE IF EXISTS nvts ADD COLUMN solution_method text;");

  /* Set the database version to 223. */

  set_db_version (223);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 223 to version 224.
 *
 * @return 0 success, -1 error.
 */
int
migrate_223_to_224 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 223. */

  if (manage_db_version () != 223)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Agents were removed entirely. */

  sql ("DELETE FROM tag_resources WHERE resource_type = 'agent';");
  sql ("DELETE FROM tag_resources_trash WHERE resource_type = 'agent';");

  sql ("DELETE FROM tags WHERE resource_type = 'agent';");
  sql ("DELETE FROM tags_trash WHERE resource_type = 'agent';");

  sql ("DELETE FROM permissions WHERE resource_type = 'agent';");
  sql ("DELETE FROM permissions_trash WHERE resource_type = 'agent';");

  sql ("UPDATE alerts SET filter = 0"
       " WHERE filter IN (SELECT id FROM filters"
       "                  WHERE type = 'agent');");
  sql ("UPDATE alerts_trash SET filter = 0"
       " WHERE filter IN (SELECT id FROM filters"
       "                  WHERE type = 'agent')"
       " AND filter_location = %i;",
       LOCATION_TABLE);
  sql ("UPDATE alerts_trash SET filter = 0"
       " WHERE filter IN (SELECT id FROM filters_trash"
       "                  WHERE type = 'agent')"
       " AND filter_location = %i;",
       LOCATION_TRASH);

  sql ("DELETE FROM filters WHERE type = 'agent';");
  sql ("DELETE FROM filters_trash WHERE type = 'agent';");

  /* Setting 'Agents Filter'. */
  sql ("DELETE FROM settings WHERE uuid = '4a1334c1-cb93-4a79-8634-103b0a50bdcd';");

  sql ("DROP TABLE IF EXISTS agents;");
  sql ("DROP TABLE IF EXISTS agents_trash;");

  /* Set the database version to 224. */

  set_db_version (224);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 224 to version 225.
 *
 * @return 0 success, -1 error.
 */
int
migrate_224_to_225 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 224. */

  if (manage_db_version () != 224)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* GMP command COMMANDS was removed. */

  sql ("DELETE FROM permissions WHERE name = 'commands';");
  sql ("DELETE FROM permissions_trash WHERE name = 'commands';");

  /* Set the database version to 225. */

  set_db_version (225);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 225 to version 226.
 *
 * @return 0 success, -1 error.
 */
int
migrate_225_to_226 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 225. */

  if (manage_db_version () != 225)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* A setting's UUID was changed to the correct length. */

  sql ("UPDATE settings"
       " SET uuid = 'ce7b121-c609-47b0-ab57-fd020a0336f4a'"
       " WHERE uuid = 'ce7b121-c609-47b0-ab57-fd020a0336f4';");

  /* Set the database version to 226. */

  set_db_version (226);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 226 to version 227.
 *
 * @return 0 success, -1 error.
 */
int
migrate_226_to_227 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 226. */

  if (manage_db_version () != 226)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The unused table port_names was removed. */

  sql ("DROP TABLE port_names;");

  /* Set the database version to 227. */

  set_db_version (227);

  sql_commit ();

  return 0;
}

/**
 * @brief Delete results for migrate_227_to_228.
 *
 * @param[in]  table  Name of table.
 *
 * @return Count of deleted rows.
 */
static int
migrate_227_to_228_delete (const char *table)
{
  int location;

  if (strcmp (table, "results") == 0)
    location = LOCATION_TABLE;
  else
    location = LOCATION_TRASH;

  return sql_int (/* Remove results, storing ids. */
                  "WITH deleted"
                  " AS (DELETE FROM %s"
                  "     WHERE EXISTS (SELECT *"
                  "                   FROM report_host_details, report_hosts"
                  "                   WHERE report_host_details.report_host"
                  "                         = report_hosts.id"
                  "                   AND report_hosts.report = %s.report"
                  "                   AND report_hosts.host = %s.host"
                  "                   AND name = 'Host dead'"
                  "                   AND value = '1')"
                  "     RETURNING id),"
                  /* Remove references to results in any tags. */
                  " dummy1"
                  " AS (DELETE FROM tag_resources"
                  "     WHERE resource_type = 'result'"
                  "     AND resource_location = %i"
                  "     AND resource IN (SELECT id FROM deleted)),"
                  /* Remove references to results in any trash tags. */
                  " dummy2"
                  " AS (DELETE FROM tag_resources_trash"
                  "     WHERE resource_type = 'result'"
                  "     AND resource_location = %i"
                  "     AND resource IN (SELECT id FROM deleted))"
                  /* Return count of deleted results. */
                  " SELECT count(*) from deleted;",
                  table,
                  table,
                  table,
                  location,
                  location);
}

/**
 * @brief Migrate the database from version 227 to version 228.
 *
 * @return 0 success, -1 error.
 */
int
migrate_227_to_228 ()
{
  int count;

  sql_begin_immediate ();

  /* Ensure that the database is currently version 227. */

  if (manage_db_version () != 227)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Dead hosts are no longer stored. */

  count = migrate_227_to_228_delete ("results");
  if (count)
    g_info ("%s: deleted %i result%s of dead report hosts",
            __func__,
            count,
            count > 1 ? "s" : "");

  count = migrate_227_to_228_delete ("results_trash");
  if (count)
    g_info ("%s: deleted %i trashcan result%s of dead report hosts",
            __func__,
            count,
            count > 1 ? "s" : "");

  count = sql_int (/* Delete "Host dead" details, getting dead report_hosts. */
                   "WITH dead_report_hosts"
                   " AS (DELETE FROM report_host_details"
                   "     WHERE name = 'Host dead'"
                   "     AND value = '1'"
                   "     RETURNING report_host),"
                   /* Delete any other details on the dead report_hosts. */
                   " dummy1"
                   " AS (DELETE FROM report_host_details"
                   "     WHERE report_host"
                   "           IN (SELECT distinct report_host"
                   "               FROM dead_report_hosts)),"
                   /* Delete dead report_hosts. */
                   " deleted"
                   " AS (DELETE FROM report_hosts"
                   "     WHERE id IN (SELECT distinct report_host"
                   "                  FROM dead_report_hosts)"
                   "     RETURNING report),"
                   /* Clear report counts for affected reports. */
                   " dummy2"
                   " AS (DELETE FROM report_counts"
                   "     WHERE report IN (SELECT distinct report"
                   "                      FROM deleted))"
                   /* Return count of dead report_hosts. */
                   " SELECT count(*) from deleted;");
  if (count)
    g_info ("%s: deleted %i dead report host%s",
            __func__,
            count,
            count > 1 ? "s" : "");

  /* Set the database version to 228. */

  set_db_version (228);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 228 to version 229.
 *
 * @return 0 success, -1 error.
 */
int
migrate_228_to_229 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 228. */

  if (manage_db_version () != 228)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Setting UUIDs now have to be unique per owner. */
  sql ("DELETE FROM settings"
       " WHERE id NOT IN (SELECT max(id) FROM settings"
       "                  GROUP BY uuid, owner);");

  sql ("ALTER TABLE settings ADD UNIQUE(uuid, owner);");

  /* Set the database version to 229. */

  set_db_version (229);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 229 to version 230.
 *
 * @return 0 success, -1 error.
 */
int
migrate_229_to_230 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 229. */

  if (manage_db_version () != 229)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  sql ("ALTER TABLE schedules DROP COLUMN initial_offset;");

  /* Set the database version to 230. */

  set_db_version (230);

  sql_commit ();

  return 0;
}

/**
 * @brief Add timezones to schedule iCalendar strings.
 *
 * @param[in]  trash  Whether to convert the trash table.
 */
static void
convert_schedules_231 (gboolean trash)
{
  iterator_t schedules;

  init_iterator (&schedules,
                 "SELECT id, icalendar, uuid, timezone FROM %s;",
                 trash ? "schedules_trash" : "schedules");

  while (next (&schedules))
    {
      schedule_t schedule;
      const char *ical_string, *schedule_id, *zone;
      icalcomponent *ical_component;
      icaltimezone *ical_zone;
      gchar *error_out;

      error_out = NULL;
      schedule = iterator_int64 (&schedules, 0);
      ical_string = iterator_string (&schedules, 1);
      schedule_id = iterator_string (&schedules, 2);
      zone = iterator_string (&schedules, 3);

      ical_zone = icalendar_timezone_from_string (zone);
      if (ical_zone == NULL)
        {
          g_warning ("%s: error converting schedule %s: timezone '%s'",
                     __func__, schedule_id, zone);
          continue;
        }

      ical_component = icalendar_from_string (ical_string,
                                              ical_zone,
                                              &error_out);
      if (ical_component == NULL)
        g_warning ("%s: error converting schedule %s: %s", __func__,
                   schedule_id, error_out);
      else
        {
          gchar *quoted_ical;

          quoted_ical
            = sql_quote (icalcomponent_as_ical_string (ical_component));

          sql ("UPDATE %s SET icalendar = '%s' WHERE id = %llu",
               trash ? "schedules_trash" : "schedules",
               quoted_ical,
               schedule);

          g_free (quoted_ical);
        }

      g_free (error_out);
    }

  cleanup_iterator (&schedules);
}

/**
 * @brief Migrate the database from version 230 to version 231.
 *
 * @return 0 success, -1 error.
 */
int
migrate_230_to_231 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 230. */

  if (manage_db_version () != 230)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Add timezones to schedule iCalendar strings. */
  convert_schedules_231 (FALSE);
  convert_schedules_231 (TRUE);

  /* Set the database version to 231. */

  set_db_version (231);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 231 to version 232.
 *
 * @return 0 success, -1 error.
 */
int
migrate_231_to_232 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 231. */

  if (manage_db_version () != 231)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Add path field to results and results_trash. */
  sql ("ALTER TABLE results ADD COLUMN path text;");
  sql ("ALTER TABLE results_trash ADD COLUMN path text;");

  /* Set path to empty string */
  sql ("UPDATE results SET path = '';");
  sql ("UPDATE results_trash SET path = '';");

  /* Set the database version to 231. */

  set_db_version (232);

  sql_commit ();

  return 0;
}

/**
 * @brief Set predefined.
 *
 * @param[in]  type   Type to update.
 * @param[in]  table  Table to update.
 *
 * @return 0 success, -1 error.
 */
int
migrate_232_to_233_set_predefined (const gchar *type, const gchar *table)
{
  GError *error;
  GDir *dir;
  const gchar *xml_path;
  gchar *dir_path;

  dir_path = g_build_filename (GVMD_FEED_DIR,
                               GMP_VERSION_FEED,
                               type,
                               NULL);

  /* Open feed import directory. */

  error = NULL;
  dir = g_dir_open (dir_path, 0, &error);
  if (dir == NULL)
    {
      g_warning ("%s: Failed to open directory '%s': %s",
                 __func__, dir_path, error->message);
      g_error_free (error);
      g_free (dir_path);
      return -1;
    }
  g_free (dir_path);

  /* Update for each file. */

  while ((xml_path = g_dir_read_name (dir)))
    if (g_str_has_prefix (xml_path, ".") == 0
        && strlen (xml_path) >= (36 /* UUID */ + strlen (".xml"))
        && g_str_has_suffix (xml_path, ".xml"))
      {
        gchar *quoted_uuid, *uuid;

        uuid = g_strndup (xml_path + strlen (xml_path) - 4 - 36, 36);
        quoted_uuid = sql_quote (uuid);
        g_free (uuid);
        sql ("UPDATE %s SET predefined = 1 WHERE uuid = '%s';",
             table, quoted_uuid);
        g_free (quoted_uuid);
      }

  /* Cleanup. */

  g_dir_close (dir);

  return 0;
}

/**
 * @brief Migrate the database from version 232 to version 233.
 *
 * @return 0 success, -1 error.
 */
int
migrate_232_to_233 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 232. */

  if (manage_db_version () != 232)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Predefined flag moved to tables. */

  sql ("ALTER TABLE report_formats ADD COLUMN predefined integer;");
  sql ("ALTER TABLE report_formats_trash ADD COLUMN predefined integer;");
  sql ("ALTER TABLE port_lists ADD COLUMN predefined integer;");
  sql ("ALTER TABLE port_lists_trash ADD COLUMN predefined integer;");
  sql ("ALTER TABLE configs ADD COLUMN predefined integer;");
  sql ("ALTER TABLE configs_trash ADD COLUMN predefined integer;");

  sql ("UPDATE report_formats SET predefined = 0;");
  sql ("UPDATE report_formats_trash SET predefined = 0;");
  sql ("UPDATE port_lists SET predefined = 0;");
  sql ("UPDATE port_lists_trash SET predefined = 0;");
  sql ("UPDATE configs SET predefined = 0;");
  sql ("UPDATE configs_trash SET predefined = 0;");

  sql ("UPDATE report_formats"
       " SET predefined = 1"
       " WHERE id IN (SELECT resource FROM resources_predefined"
       "              WHERE resource_type = 'report_format');");

  migrate_232_to_233_set_predefined ("report_formats", "report_formats");
  migrate_232_to_233_set_predefined ("configs", "configs");
  migrate_232_to_233_set_predefined ("port_lists", "port_lists");

  migrate_232_to_233_set_predefined ("report_formats", "report_formats_trash");
  migrate_232_to_233_set_predefined ("configs", "configs_trash");
  migrate_232_to_233_set_predefined ("port_lists", "port_lists_trash");

  sql ("DROP TABLE resources_predefined;");

  /* Set the database version to 232. */

  set_db_version (233);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 233 to version 234.
 *
 * @return 0 success, -1 error.
 */
int
migrate_233_to_234 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 233. */

  if (manage_db_version () != 233)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Support for GMP Scanners was removed, including setting "GMP Slave
   * Check Period" and various report slave columns. */

  /* Delete setting. */
  sql ("DELETE FROM settings WHERE uuid = '63adb79a-62ae-11e9-91ba-28d24461215b';");

  /* Drop columns. */
  sql ("ALTER TABLE reports"
       " DROP column slave_task_uuid,"
       " DROP column slave_uuid,"
       " DROP column slave_name,"
       " DROP column slave_host,"
       " DROP column slave_port;");

  /* Convert existing GMP Scanners to OSP Sensors. */
  sql ("UPDATE scanners SET type = 5 WHERE type = 4;");
  sql ("UPDATE scanners_trash SET type = 5 WHERE type = 4;");

  /* Set the database version to 234. */

  set_db_version (234);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 234 to version 235.
 *
 * @return 0 success, -1 error.
 */
int
migrate_234_to_235 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 234. */

  if (manage_db_version () != 234)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Support of multiple individual selectable severity classification ranges
   * was removed. Therefore any entry in settings table where "Severity Class"
   * is configured, can be removed. This setting has a specific uuid. */

  /* Delete any setting for "Severity Class" . */
  sql ("DELETE FROM settings WHERE uuid = 'f16bb236-a32d-4cd5-a880-e0fcf2599f59';");

  /* Set the database version to 235. */

  set_db_version (235);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 235 to version 236.
 *
 * @return 0 success, -1 error.
 */
int
migrate_235_to_236 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 235. */

  if (manage_db_version () != 235)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Replace any result type "Debug Message" by "Error Message". */

  sql ("UPDATE results SET type = 'Error Message' WHERE type = 'Debug Message';");
  sql ("UPDATE results_trash SET type = 'Error Message' WHERE type = 'Debug Message';");

  /* Set the database version to 236. */

  set_db_version (236);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 236 to version 237.
 *
 * @return 0 success, -1 error.
 */
int
migrate_236_to_237 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 236. */

  if (manage_db_version () != 236)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* This previously added a "score" column to the nvts table */

  /* Set the database version to 237. */

  set_db_version (237);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 237 to version 238.
 *
 * @return 0 success, -1 error.
 */
int
migrate_237_to_238 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 237. */

  if (manage_db_version () != 237)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* This previously added a "score" column to the results and results_trash
   * tables. */

  /* Set the database version to 238. */

  set_db_version (238);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 238 to version 239.
 *
 * @return 0 success, -1 error.
 */
int
migrate_238_to_239 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 238. */

  if (manage_db_version () != 238)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Table targets(_trash) got a allow_simult_ips_same_host column. */

  sql ("ALTER TABLE targets ADD COLUMN"
       " allow_simult_ips_same_host integer DEFAULT 1;");

  sql ("ALTER TABLE targets_trash ADD COLUMN"
       " allow_simult_ips_same_host integer DEFAULT 1;");

  /* Set the database version to 239. */

  set_db_version (239);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 239 to version 240.
 *
 * @return 0 success, -1 error.
 */
int
migrate_239_to_240 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 239. */

  if (manage_db_version () != 239)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Table results also got a score column, for extended severities. */

  sql ("DROP VIEW IF EXISTS vulns;");

  /* Set the database version to 240. */

  set_db_version (240);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 240 to version 241.
 *
 * @return 0 success, -1 error.
 */
int
migrate_240_to_241 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 240. */

  if (manage_db_version () != 240)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Rename allow_simult_ips_same_host column to allow_simultaneous_ips */

  sql ("ALTER TABLE targets RENAME COLUMN"
       " allow_simult_ips_same_host TO allow_simultaneous_ips;");

  sql ("ALTER TABLE targets_trash RENAME COLUMN"
       " allow_simult_ips_same_host TO allow_simultaneous_ips;");

  /* Set the database version to 241. */

  set_db_version (241);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 241 to version 242.
 *
 * @return 0 success, -1 error.
 */
int
migrate_241_to_242 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 241. */

  if (manage_db_version () != 241)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Remove score columns from results and nvts if they were added in
   *  migrations to previous versions.
   */

  sql ("DROP VIEW IF EXISTS vulns;");

  sql ("ALTER TABLE nvts DROP COLUMN IF EXISTS score;");

  sql ("ALTER TABLE results DROP COLUMN IF EXISTS score;");

  sql ("ALTER TABLE results_trash DROP COLUMN IF EXISTS score;");

  /* Change the vt_severities table to use a CVSS score
   * if it already exists (migrating from a 21.04 development version) */
  if (sql_int ("SELECT EXISTS (SELECT * FROM information_schema.tables"
               "               WHERE table_catalog = '%s'"
               "               AND table_schema = 'public'"
               "               AND table_name = 'vt_severities')"
               " ::integer;",
               sql_database ()))
    {
      sql ("ALTER TABLE vt_severities ALTER COLUMN score"
           " SET DATA TYPE double precision;");
      sql ("UPDATE vt_severities"
           " SET score = round((score / 10.0)::numeric, 1);");
    }

  /* Set the database version to 242. */

  set_db_version (242);

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
  {214, migrate_213_to_214},
  {215, migrate_214_to_215},
  {216, migrate_215_to_216},
  {217, migrate_216_to_217},
  {218, migrate_217_to_218},
  {219, migrate_218_to_219},
  {220, migrate_219_to_220},
  {221, migrate_220_to_221},
  {222, migrate_221_to_222},
  {223, migrate_222_to_223},
  {224, migrate_223_to_224},
  {225, migrate_224_to_225},
  {226, migrate_225_to_226},
  {227, migrate_226_to_227},
  {228, migrate_227_to_228},
  {229, migrate_228_to_229},
  {230, migrate_229_to_230},
  {231, migrate_230_to_231},
  {232, migrate_231_to_232},
  {233, migrate_232_to_233},
  {234, migrate_233_to_234},
  {235, migrate_234_to_235},
  {236, migrate_235_to_236},
  {237, migrate_236_to_237},
  {238, migrate_237_to_238},
  {239, migrate_238_to_239},
  {240, migrate_239_to_240},
  {241, migrate_240_to_241},
  {242, migrate_241_to_242},
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
manage_migrate_needs_timezone (GSList *log_config,
                               const db_conn_info_t *database)
{
  int db_version;
  g_log_set_handler (
    G_LOG_DOMAIN, ALL_LOG_LEVELS, (GLogFunc) gvm_log_func, log_config);
  init_manage_process (database);
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
manage_migrate (GSList *log_config, const db_conn_info_t *database)
{
  migrator_t *migrators;
  /* The version on the disk. */
  int old_version, old_scap_version, old_cert_version;
  /* The version that this program requires. */
  int new_version, new_scap_version, new_cert_version;
  int version_current = 0, scap_version_current = 0, cert_version_current = 0;

  g_log_set_handler (
    G_LOG_DOMAIN, ALL_LOG_LEVELS, (GLogFunc) gvm_log_func, log_config);

  init_manage_process (database);

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
                 __func__);
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
  init_manage_process (database);
  g_info ("   Analyzing the database. This may take up to several hours.");
  sql ("ANALYZE;");

  cleanup_manage_process (TRUE);
  return 0;
}
