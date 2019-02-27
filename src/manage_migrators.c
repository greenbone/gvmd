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

#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <glib/gstdio.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/param.h>
#ifdef __FreeBSD__
#include <sys/wait.h>
#endif
#include <ctype.h>
#include <dirent.h>

#include "manage_sql.h"
#include "utils.h"
#include "sql.h"

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
  int version;         ///< Version that the migrator produces.
  int (*function) ();  ///< Function that does the migration.  NULL if too hard.
} migrator_t;

/* Functions. */

/** @todo May be better ensure a ROLLBACK when functions like "sql" fail.
 *
 * Currently the SQL functions abort on failure.  This a general problem,
 * not just for migrators, so perhaps the SQL interface should keep
 * track of the transaction, and rollback before aborting. */

/**
 * @brief Migrate the database from version 145 to version 146.
 *
 * @return 0 success, -1 error.
 */
int
migrate_145_to_146 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 145. */

  if (manage_db_version () != 145)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The view result_overrides changed. */
  sql ("DROP VIEW IF EXISTS result_new_severities;");
  sql ("DROP VIEW IF EXISTS result_overrides;");
  sql ("DELETE FROM report_counts;");

  /* Set the database version to 146. */

  set_db_version (146);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 146 to version 147.
 *
 * @return 0 success, -1 error.
 */
int
migrate_146_to_147 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 146. */

  if (manage_db_version () != 146)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The report_counts table got a min_qod column. */
  sql ("ALTER TABLE report_counts ADD COLUMN min_qod INTEGER;");
  sql ("UPDATE report_counts SET min_qod = %d;", MIN_QOD_DEFAULT);

  /* Set the database version to 147. */

  set_db_version (147);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 147 to version 148.
 *
 * @return 0 success, -1 error.
 */
int
migrate_147_to_148 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 147. */

  if (manage_db_version () != 147)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The "generate" scripts of all report formats must now be executable. */

  check_generate_scripts ();

  /* Set the database version to 148. */

  set_db_version (148);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 148 to version 149.
 *
 * @return 0 success, -1 error.
 */
int
migrate_148_to_149 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 148. */

  if (manage_db_version () != 148)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The tasks table got a scanner_location column. */
  sql ("ALTER TABLE tasks ADD COLUMN scanner_location INTEGER;");
  sql ("UPDATE tasks SET scanner_location = " G_STRINGIFY (LOCATION_TABLE));

  /* Set the database version to 149. */

  set_db_version (149);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 149 to version 150.
 *
 * @return 0 success, -1 error.
 */
int
migrate_149_to_150 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 149. */

  if (manage_db_version () != 149)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The view result_new_severities changed. */
  sql ("DROP VIEW IF EXISTS result_new_severities;");

  /* Set the database version to 150. */

  set_db_version (150);

  sql_commit ();

  return 0;
}

/**
 * @brief Permission SQL for migrate_150_to_151.
 *
 * @param[in]  name  Name.
 * @param[in]  role  Role.
 */
#define INSERT_PERMISSION(name, role)                                          \
  sql ("INSERT INTO permissions"                                               \
       " (uuid, owner, name, comment, resource_type, resource, resource_uuid," \
       "  resource_location, subject_type, subject, subject_location,"         \
       "  creation_time, modification_time)"                                   \
       " VALUES"                                                               \
       " (make_uuid (), NULL, '" G_STRINGIFY (name) "', '', '',"               \
       "  0, '', " G_STRINGIFY (LOCATION_TABLE) ", 'role',"                    \
       "  (SELECT id FROM roles WHERE uuid = '%s'),"                           \
       "  " G_STRINGIFY (LOCATION_TABLE) ", m_now (), m_now ());",             \
       role)

/**
 * @brief Migrate the database from version 150 to version 151.
 *
 * @return 0 success, -1 error.
 */
int
migrate_150_to_151 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 150. */

  if (manage_db_version () != 150)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Commands GET_ASSETS and DELETE_ASSET were added. */

  INSERT_PERMISSION (get_assets, ROLE_UUID_ADMIN);
  INSERT_PERMISSION (get_assets, ROLE_UUID_OBSERVER);
  INSERT_PERMISSION (get_assets, ROLE_UUID_SUPER_ADMIN);
  INSERT_PERMISSION (get_assets, ROLE_UUID_USER);

  INSERT_PERMISSION (delete_asset, ROLE_UUID_ADMIN);
  INSERT_PERMISSION (delete_asset, ROLE_UUID_SUPER_ADMIN);
  INSERT_PERMISSION (delete_asset, ROLE_UUID_USER);

  /* Set the database version to 151. */

  set_db_version (151);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 151 to version 152.
 *
 * @return 0 success, -1 error.
 */
int
migrate_151_to_152 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 151. */

  if (manage_db_version () != 151)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Command CREATE_ASSET was added. */

  INSERT_PERMISSION (create_asset, ROLE_UUID_ADMIN);
  INSERT_PERMISSION (create_asset, ROLE_UUID_SUPER_ADMIN);
  INSERT_PERMISSION (create_asset, ROLE_UUID_USER);

  /* Set the database version to 152. */

  set_db_version (152);

  sql_commit ();

  return 0;
}

/**
 * @brief Permission SQL for migrate_152_to_153.
 *
 * @param[in]  name  Name.
 * @param[in]  role  Role.
 */
#define DELETE_PERMISSION(name, role)                                          \
  sql ("DELETE FROM permissions"                                               \
       " WHERE subject_type = 'role'"                                          \
       " AND subject_location = " G_STRINGIFY (LOCATION_TABLE)                 \
       " AND subject = (SELECT id FROM roles WHERE uuid = '%s')"               \
       " AND name = '" G_STRINGIFY (name) "';",                                \
       role)

/**
 * @brief Migrate the database from version 152 to version 153.
 *
 * @return 0 success, -1 error.
 */
int
migrate_152_to_153 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 152. */

  if (manage_db_version () != 152)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Command MODIFY_ASSET was added.  Also remove permissions added in previous
   * two migrators on roles that have "Everything". */

  INSERT_PERMISSION (modify_asset, ROLE_UUID_USER);

  DELETE_PERMISSION (create_asset, ROLE_UUID_ADMIN);
  DELETE_PERMISSION (create_asset, ROLE_UUID_SUPER_ADMIN);
  DELETE_PERMISSION (get_assets, ROLE_UUID_ADMIN);
  DELETE_PERMISSION (get_assets, ROLE_UUID_SUPER_ADMIN);
  DELETE_PERMISSION (delete_asset, ROLE_UUID_ADMIN);
  DELETE_PERMISSION (delete_asset, ROLE_UUID_SUPER_ADMIN);

  /* Set the database version to 153. */

  set_db_version (153);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 152 to version 153.
 *
 * @return 0 success, -1 error.
 */
int
migrate_153_to_154 ()
{
  const char *primary_key_type = sql_is_sqlite3 () ? "INTEGER" : "SERIAL";
  iterator_t credentials;

  sql_begin_immediate ();

  /* Ensure that the database is currently version 153. */

  if (manage_db_version () != 153)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Create new credentials tables */
  sql ("CREATE TABLE credentials"
       " (id %s PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer%s,"
       "  name text NOT NULL,"
       "  comment text,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  type text);",
       primary_key_type,
       sql_is_sqlite3() ? "" : " REFERENCES users (id) ON DELETE RESTRICT");

  sql ("CREATE TABLE credentials_trash"
       " (id %s PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  owner integer%s,"
       "  name text NOT NULL,"
       "  comment text,"
       "  creation_time integer,"
       "  modification_time integer,"
       "  type text);",
       primary_key_type,
       sql_is_sqlite3() ? "" : " REFERENCES users (id) ON DELETE RESTRICT");

  sql ("CREATE TABLE credentials_data"
       " (id %s PRIMARY KEY,"
       "  credential INTEGER%s,"
       "  type TEXT,"
       "  value TEXT);",
       primary_key_type,
       sql_is_sqlite3()
        ? ""
        : " REFERENCES credentials (id) ON DELETE RESTRICT");

  sql ("CREATE TABLE credentials_trash_data"
       " (id %s PRIMARY KEY,"
       "  credential INTEGER%s,"
       "  type TEXT,"
       "  value TEXT);",
       primary_key_type,
       sql_is_sqlite3()
        ? ""
        : " REFERENCES credentials_trash (id) ON DELETE RESTRICT");

  /* Copy basic data from old tables */
  sql ("INSERT INTO credentials"
       " (id, uuid, owner, name, comment, creation_time, modification_time)"
       " SELECT"
       "   id, uuid, owner, name, comment, creation_time, modification_time"
       " FROM lsc_credentials;");

  sql ("INSERT INTO credentials_trash"
       " (id, uuid, owner, name, comment, creation_time, modification_time)"
       " SELECT"
       "   id, uuid, owner, name, comment, creation_time, modification_time"
       " FROM lsc_credentials_trash;");

  /* Copy credentials data */
  sql ("INSERT INTO credentials_data (credential, type, value)"
       " SELECT id, 'username', login FROM lsc_credentials"
       "  WHERE login IS NOT NULL;");

  sql ("INSERT INTO credentials_trash_data (credential, type, value)"
       " SELECT id, 'username', login FROM lsc_credentials_trash"
       "  WHERE login IS NOT NULL;");

  sql ("INSERT INTO credentials_data (credential, type, value)"
       " SELECT id, 'password', password FROM lsc_credentials"
       "  WHERE password IS NOT NULL AND private_key != ';;encrypted;;';");

  sql ("INSERT INTO credentials_trash_data (credential, type, value)"
       " SELECT id, 'password', password FROM lsc_credentials_trash"
       "  WHERE password IS NOT NULL AND private_key != ';;encrypted;;';");

  sql ("INSERT INTO credentials_data (credential, type, value)"
       " SELECT id, 'private_key', private_key FROM lsc_credentials"
       "  WHERE password IS NOT NULL AND private_key != ';;encrypted;;';");

  sql ("INSERT INTO credentials_trash_data (credential, type, value)"
       " SELECT id, 'private_key', private_key FROM lsc_credentials_trash"
       "  WHERE password IS NOT NULL AND private_key != ';;encrypted;;';");

  sql ("INSERT INTO credentials_data (credential, type, value)"
       " SELECT id, 'secret', password FROM lsc_credentials"
       "  WHERE password IS NOT NULL AND private_key = ';;encrypted;;';");

  sql ("INSERT INTO credentials_trash_data (credential, type, value)"
       " SELECT id, 'secret', password FROM lsc_credentials_trash"
       "  WHERE password IS NOT NULL AND private_key = ';;encrypted;;';");

  /* For Postgres, reset sequences because we messed with SERIAL column "id". */

  if (sql_is_sqlite3 () == 0)
    {
      sql ("SELECT setval ('credentials_id_seq',"
           "               (SELECT max (id) + 1 FROM credentials));");

      sql ("SELECT setval ('credentials_trash_id_seq',"
           "               (SELECT max (id) + 1 FROM credentials_trash));");

      sql ("SELECT setval ('credentials_data_id_seq',"
           "               (SELECT max (id) + 1 FROM credentials_data));");

      sql ("SELECT setval ('credentials_trash_data_id_seq',"
           "               (SELECT max (id) + 1"
           "                FROM credentials_trash_data));");
    }

  /* Set type for existing credentials */
  init_iterator (&credentials,
                 "SELECT id, password, private_key, 0"
                 " FROM lsc_credentials"
                 " UNION ALL"
                 " SELECT id, password, private_key, 1"
                 " FROM lsc_credentials_trash;");

  while (next (&credentials))
    {
      credential_t credential;
      int is_trash;
      const char *password, *privkey;
      const char *type;

      credential = iterator_int64 (&credentials, 0);
      password = iterator_string (&credentials, 1);
      privkey = iterator_string (&credentials, 2);
      is_trash = iterator_int (&credentials, 3);

      if (privkey == NULL)
        type = "up";
      else if (strcmp (privkey, ";;encrypted;;"))
        type = "usk";
      else
        {
          if (!credentials.crypt_ctx)
            credentials.crypt_ctx = lsc_crypt_new ();

          if (lsc_crypt_get_private_key (credentials.crypt_ctx, password))
            type = "usk";
          else
            type = "up";
        }

      sql ("UPDATE %s SET type = '%s' WHERE id = %llu;",
           is_trash ? "credentials_trash" : "credentials",
           type, credential);
    }
  cleanup_iterator (&credentials);

  /* Remove the old tables */
  sql ("DROP TABLE lsc_credentials;");
  sql ("DROP TABLE lsc_credentials_trash;");

  /* Update Tags */
  sql ("UPDATE tags SET resource_type = 'credential'"
       " WHERE resource_type = 'lsc_credential';");
  sql ("UPDATE tags_trash SET resource_type = 'credential'"
       " WHERE resource_type = 'lsc_credential';");

  /* Update permissions */
  sql ("UPDATE permissions SET name = 'create_credential'"
       " WHERE name = 'create_lsc_credential';");
  sql ("UPDATE permissions SET name = 'delete_credential'"
       " WHERE name = 'delete_lsc_credential';");
  sql ("UPDATE permissions SET name = 'get_credentials'"
       " WHERE name = 'get_lsc_credentials';");
  sql ("UPDATE permissions SET name = 'modify_credential'"
       " WHERE name = 'modify_lsc_credential';");

  /* This should have also done the renaming in column resource_type.  Done
   * in migrate_185_to_186. */

  sql ("UPDATE permissions_trash SET name = 'create_credential'"
       " WHERE name = 'create_lsc_credential';");
  sql ("UPDATE permissions_trash SET name = 'delete_credential'"
       " WHERE name = 'delete_lsc_credential';");
  sql ("UPDATE permissions_trash SET name = 'get_credentials'"
       " WHERE name = 'get_lsc_credentials';");
  sql ("UPDATE permissions_trash SET name = 'modify_credential'"
       " WHERE name = 'modify_lsc_credential';");

  /* Set the database version to 154. */

  set_db_version (154);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 154 to version 155.
 *
 * @return 0 success, -1 error.
 */
int
migrate_154_to_155 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 154. */

  if (manage_db_version () != 154)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* r23581 added ALERT_METHOD_START_TASK in the middle of alert_method_t,
   * instead of at the end.  Adjust alerts accordingly.  r23581 was released
   * first with 6.1+beta2 which had db version 155, so it's safe to do this
   * adjustment to any database that is older than 155. */
  sql ("UPDATE alerts SET method = method + 1 WHERE method >= 4;");

  /* Reports got a new column "flags". */
  sql ("ALTER TABLE reports ADD COLUMN flags INTEGER;");
  sql ("UPDATE reports SET flags = 0;");

  /* Set the database version to 155. */

  set_db_version (155);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 155 to version 156.
 *
 * @return 0 success, -1 error.
 */
int
migrate_155_to_156 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 155. */

  if (manage_db_version () != 155)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  if (sql_is_sqlite3 ())
    {
      /* Remove and rename columns by copying tables in SQLite */
      /* Rename old targets tables. */
      sql ("ALTER TABLE targets RENAME TO targets_155;");
      sql ("ALTER TABLE targets_trash RENAME TO targets_trash_155;");

      /* Create new targets tables */
      sql ("CREATE TABLE IF NOT EXISTS targets"
           " (id INTEGER PRIMARY KEY,"
           "  uuid text UNIQUE NOT NULL,"
           "  owner integer,"
           "  name text NOT NULL,"
           "  hosts text,"
           "  exclude_hosts text,"
           "  reverse_lookup_only integer,"
           "  reverse_lookup_unify integer,"
           "  comment text,"
           "  port_list integer,"
           "  alive_test integer,"
           "  creation_time integer,"
           "  modification_time integer);");

      sql ("CREATE TABLE IF NOT EXISTS targets_trash"
           " (id INTEGER PRIMARY KEY,"
           "  uuid text UNIQUE NOT NULL,"
           "  owner integer,"
           "  name text NOT NULL,"
           "  hosts text,"
           "  exclude_hosts text,"
           "  reverse_lookup_only integer,"
           "  reverse_lookup_unify integer,"
           "  comment text,"
           "  port_list integer,"
           "  port_list_location integer,"
           "  alive_test integer,"
           "  creation_time integer,"
           "  modification_time integer);");

      sql ("CREATE TABLE IF NOT EXISTS targets_login_data"
           " (id INTEGER PRIMARY KEY,"
           "  target INTEGER,"
           "  type TEXT,"
           "  credential INTEGER,"
           "  port INTEGER);");

      sql ("CREATE TABLE IF NOT EXISTS targets_trash_login_data"
           " (id INTEGER PRIMARY KEY,"
           "  target INTEGER,"
           "  type TEXT,"
           "  credential INTEGER,"
           "  port INTEGER,"
           "  credential_location INTEGER);");

      /* Copy existing basic data */
      sql ("INSERT INTO targets"
          " (id, uuid, owner, name, hosts, exclude_hosts,"
          "  reverse_lookup_only, reverse_lookup_unify, comment,"
          "  port_list, alive_test, creation_time, modification_time)"
          " SELECT id, uuid, owner, name, hosts, exclude_hosts,"
          "  reverse_lookup_only, reverse_lookup_unify, comment,"
          "  port_range, alive_test, creation_time, modification_time"
          " FROM targets_155;");

      sql ("INSERT INTO targets_trash"
          " (id, uuid, owner, name, hosts, exclude_hosts,"
          "  reverse_lookup_only, reverse_lookup_unify, comment,"
          "  port_list, alive_test, creation_time, modification_time)"
          " SELECT id, uuid, owner, name, hosts, exclude_hosts,"
          "  reverse_lookup_only, reverse_lookup_unify, comment,"
          "  port_range, alive_test, creation_time, modification_time"
          " FROM targets_trash_155;");

      /* Copy existing credentials data */
      sql ("INSERT INTO targets_login_data"
          " (target, type, credential, port)"
          " SELECT id, 'ssh', lsc_credential, CAST (ssh_port AS integer)"
          " FROM targets_155 WHERE lsc_credential != 0;");

      sql ("INSERT INTO targets_login_data"
          " (target, type, credential, port)"
          " SELECT id, 'smb', smb_lsc_credential, 0"
          " FROM targets_155 WHERE smb_lsc_credential != 0;");

      sql ("INSERT INTO targets_login_data"
          " (target, type, credential, port)"
          " SELECT id, 'esxi', esxi_lsc_credential, 0"
          " FROM targets_155 WHERE esxi_lsc_credential != 0;");

      /* Copy existing trash credentials data */
      sql ("INSERT INTO targets_trash_login_data"
          " (target, type, credential, port, credential_location)"
          " SELECT id, 'ssh', lsc_credential, CAST (ssh_port AS integer),"
          "        ssh_location"
          " FROM targets_trash_155 WHERE lsc_credential != 0;");

      sql ("INSERT INTO targets_trash_login_data"
          " (target, type, credential, port, credential_location)"
          " SELECT id, 'smb', smb_lsc_credential, 0, smb_location"
          " FROM targets_trash_155 WHERE smb_lsc_credential != 0;");

      sql ("INSERT INTO targets_trash_login_data"
          " (target, type, credential, port, credential_location)"
          " SELECT id, 'esxi', esxi_lsc_credential, 0, esxi_location"
          " FROM targets_trash_155 WHERE esxi_lsc_credential != 0;");

      /* Remove old tables */
      sql ("DROP TABLE targets_155;");
      sql ("DROP TABLE targets_trash_155;");
    }
  else
    {
      /* Use ALTER TABLE to remove and rename columns in Postgres */
      /* Create login data tables */
      sql ("CREATE TABLE IF NOT EXISTS targets_login_data"
           " (id SERIAL PRIMARY KEY,"
           "  target INTEGER REFERENCES targets (id),"
           "  type TEXT,"
           "  credential INTEGER REFERENCES credentials (id),"
           "  port INTEGER);");

      sql ("CREATE TABLE IF NOT EXISTS targets_trash_login_data"
           " (id SERIAL PRIMARY KEY,"
           "  target INTEGER REFERENCES targets_trash (id),"
           "  type TEXT,"
           "  credential INTEGER,"
           "  port INTEGER,"
           "  credential_location INTEGER);");

      /* Copy existing credentials data */
      sql ("INSERT INTO targets_login_data"
           " (target, type, credential, port)"
           " SELECT id, 'ssh', lsc_credential, CAST (ssh_port AS integer)"
           " FROM targets WHERE lsc_credential != 0;");

      sql ("INSERT INTO targets_login_data"
           " (target, type, credential, port)"
           " SELECT id, 'smb', smb_lsc_credential, 0"
           " FROM targets WHERE smb_lsc_credential != 0;");

      sql ("INSERT INTO targets_login_data"
           " (target, type, credential, port)"
           " SELECT id, 'esxi', esxi_lsc_credential, 0"
           " FROM targets WHERE esxi_lsc_credential != 0;");

      /* Copy existing trash credentials data */
      sql ("INSERT INTO targets_trash_login_data"
           " (target, type, credential, port, credential_location)"
           " SELECT id, 'ssh', lsc_credential, CAST (ssh_port AS integer),"
           "        ssh_location"
           " FROM targets_trash WHERE lsc_credential != 0;");

      sql ("INSERT INTO targets_trash_login_data"
           " (target, type, credential, port, credential_location)"
           " SELECT id, 'smb', smb_lsc_credential, 0, smb_location"
           " FROM targets_trash WHERE smb_lsc_credential != 0;");

      sql ("INSERT INTO targets_trash_login_data"
           " (target, type, credential, port, credential_location)"
           " SELECT id, 'esxi', esxi_lsc_credential, 0, esxi_location"
           " FROM targets_trash WHERE esxi_lsc_credential != 0;");

      /* Drop and remove now unused columns */
      sql ("ALTER TABLE targets DROP COLUMN lsc_credential;");
      sql ("ALTER TABLE targets DROP COLUMN ssh_port;");
      sql ("ALTER TABLE targets DROP COLUMN smb_lsc_credential;");
      sql ("ALTER TABLE targets DROP COLUMN esxi_lsc_credential;");
      sql ("ALTER TABLE targets RENAME COLUMN port_range TO port_list;");

      sql ("ALTER TABLE targets_trash DROP COLUMN lsc_credential;");
      sql ("ALTER TABLE targets_trash DROP COLUMN ssh_location;");
      sql ("ALTER TABLE targets_trash DROP COLUMN ssh_port;");
      sql ("ALTER TABLE targets_trash DROP COLUMN smb_lsc_credential;");
      sql ("ALTER TABLE targets_trash DROP COLUMN smb_location;");
      sql ("ALTER TABLE targets_trash DROP COLUMN esxi_lsc_credential;");
      sql ("ALTER TABLE targets_trash DROP COLUMN esxi_location;");
      sql ("ALTER TABLE targets_trash RENAME COLUMN port_range TO port_list;");
    }

  /* Set the database version to 156. */

  set_db_version (156);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 156 to version 157.
 *
 * @return 0 success, -1 error.
 */
int
migrate_156_to_157 ()
{
  iterator_t slaves;
  sql_begin_immediate ();

  /* Ensure that the database is currently version 156. */

  if (manage_db_version () != 156)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Add new columns to slaves tables. */
  if (sql_is_sqlite3 ())
    {
      sql ("ALTER TABLE slaves ADD COLUMN credential INTEGER;");
    }
  else
    {
      sql ("ALTER TABLE slaves ADD COLUMN credential INTEGER"
           " REFERENCES credentials (id) ON DELETE RESTRICT;");
    }
  sql ("ALTER TABLE slaves_trash ADD COLUMN credential INTEGER;");
  sql ("ALTER TABLE slaves_trash ADD COLUMN credential_location INTEGER;");

  /* Create new credentials. */
  init_iterator (&slaves,
                 "SELECT id, name, login, password, owner FROM slaves;");

  while (next (&slaves))
    {
      resource_t slave;
      const char *name, *login, *password;
      user_t owner;
      credential_t new_credential;
      gchar *quoted_name, *quoted_login;

      slave = iterator_int64 (&slaves, 0);
      name = iterator_string (&slaves, 1);
      login = iterator_string (&slaves, 2);
      password = iterator_string (&slaves, 3);
      owner = iterator_int64 (&slaves, 4);

      quoted_name = sql_quote (name);
      quoted_login = sql_quote (login);

      if (sql_int ("SELECT count(*) FROM credentials"
                   " WHERE name = 'Credential for Slave %s'"
                   "   AND owner = %llu;",
                   quoted_name, owner))
        sql ("INSERT INTO credentials"
             " (uuid, name, owner, comment, type,"
             "  creation_time, modification_time)"
             " VALUES"
             " (make_uuid (),"
             "  uniquify ('credential', 'Credential for Slave %s', %llu, ''),"
             "  %llu, 'Autogenerated by migration', 'up',"
             "  m_now (), m_now ());",
             quoted_name, owner, owner);
      else
        sql ("INSERT INTO credentials"
             " (uuid, name, owner, comment, type,"
             "  creation_time, modification_time)"
             " VALUES"
             " (make_uuid (), 'Credential for Slave %s',"
             "  %llu, 'Autogenerated by migration', 'up',"
             "  m_now (), m_now ());",
             quoted_name, owner);

      new_credential = sql_last_insert_id ();

      sql ("UPDATE slaves SET credential = %llu WHERE id = %llu;",
           new_credential, slave);

      sql ("INSERT INTO credentials_data (credential, type, value)"
           " VALUES (%llu, 'username', '%s');",
           new_credential, quoted_login);

      if (disable_encrypted_credentials)
        {
          gchar *quoted_password;
          quoted_password = sql_quote (password);
          sql ("INSERT INTO credentials_data (credential, type, value)"
               " VALUES (%llu, 'password', '%s');",
               new_credential, quoted_password);
          g_free (quoted_password);
        }
      else
        {
          char *secret;
          gchar *quoted_secret;

          if (!slaves.crypt_ctx)
            slaves.crypt_ctx = lsc_crypt_new ();

          secret = lsc_crypt_encrypt (slaves.crypt_ctx,
                                      "password", password, NULL);
          if (!secret)
            {
              g_free (quoted_name);
              g_free (quoted_login);
              cleanup_iterator (&slaves);
              sql_rollback ();
              return -1;
            }
          quoted_secret = sql_quote (secret);
          sql ("INSERT INTO credentials_data (credential, type, value)"
               " VALUES (%llu, 'secret', '%s');",
              new_credential, quoted_secret);
          g_free (quoted_secret);
        }

      sql ("INSERT INTO"
           " permissions (uuid, owner, name,"
           "              comment, resource_type, resource,"
           "              resource_uuid,"
           "              resource_location, subject_type, subject,"
           "              subject_location, creation_time, modification_time)"
           " SELECT make_uuid(), owner, 'get_credentials',"
           "         'Autogenerated by Slave migration', 'credential', %llu,"
           "         (SELECT uuid FROM credentials WHERE id=%llu),"
           "         " G_STRINGIFY (LOCATION_TABLE) ", subject_type, subject,"
           "         subject_location, m_now (), m_now ()"
           " FROM permissions"
           " WHERE resource = %llu"
           "   AND resource_type = 'slave'"
           "   AND resource_location = " G_STRINGIFY (LOCATION_TABLE)
           " GROUP BY owner, subject_type, subject, subject_location;",
           new_credential, new_credential, slave);

      sql ("INSERT INTO"
           " permissions_trash (uuid, owner, name,"
           "                    comment, resource_type, resource,"
           "                    resource_uuid,"
           "                    resource_location, subject_type, subject,"
           "                    subject_location,"
           "                    creation_time, modification_time)"
           " SELECT make_uuid(), owner, 'get_credentials',"
           "         'Autogenerated by Slave migration', 'credential', %llu,"
           "         (SELECT uuid FROM credentials WHERE id=%llu),"
           "         " G_STRINGIFY (LOCATION_TABLE) ", subject_type, subject,"
           "         subject_location, m_now (), m_now ()"
           " FROM permissions_trash"
           " WHERE resource = %llu"
           "   AND resource_type = 'slave'"
           "   AND resource_location = " G_STRINGIFY (LOCATION_TABLE)
           " GROUP BY owner, subject_type, subject, subject_location;",
           new_credential, new_credential, slave);

      g_free (quoted_name);
      g_free (quoted_login);
    }
  cleanup_iterator (&slaves);

  /* Create new credentials for trashcan. */
  init_iterator (&slaves,
                 "SELECT id, name, login, password, owner"
                 " FROM slaves_trash;");

  while (next (&slaves))
    {
      resource_t slave;
      const char *name, *login, *password;
      user_t owner;
      credential_t new_credential;
      gchar *quoted_name, *quoted_login;

      slave = iterator_int64 (&slaves, 0);
      name = iterator_string (&slaves, 1);
      login = iterator_string (&slaves, 2);
      password = iterator_string (&slaves, 3);
      owner = iterator_int64 (&slaves, 4);

      quoted_name = sql_quote (name);
      quoted_login = sql_quote (login);

      sql ("INSERT INTO credentials_trash"
           " (uuid, name, owner, comment, type,"
           "  creation_time, modification_time)"
           " VALUES"
           " (make_uuid (), 'Credential for Slave %s',"
           "  %llu, 'Autogenerated by migration', 'up',"
           "  m_now (), m_now ());",
           quoted_name, owner);

      new_credential = sql_last_insert_id ();

      sql ("UPDATE slaves_trash SET credential = %llu,"
           " credential_location = " G_STRINGIFY (LOCATION_TRASH)
           " WHERE id = %llu;",
           new_credential, slave);

      sql ("INSERT INTO credentials_trash_data (credential, type, value)"
           " VALUES (%llu, 'username', '%s');",
           new_credential, quoted_login);

      if (disable_encrypted_credentials)
        {
          gchar *quoted_password;
          quoted_password = sql_quote (password);
          sql ("INSERT INTO credentials_trash_data (credential, type, value)"
               " VALUES (%llu, 'password', '%s');",
               new_credential, quoted_password);
          g_free (quoted_password);
        }
      else
        {
          char *secret;
          gchar *quoted_secret;

          if (!slaves.crypt_ctx)
            slaves.crypt_ctx = lsc_crypt_new ();

          secret = lsc_crypt_encrypt (slaves.crypt_ctx,
                                      "password", password, NULL);
          if (!secret)
            {
              g_free (quoted_name);
              g_free (quoted_login);
              cleanup_iterator (&slaves);
              sql_rollback ();
              return -1;
            }
          quoted_secret = sql_quote (secret);
          sql ("INSERT INTO credentials_trash_data (credential, type, value)"
               " VALUES (%llu, 'secret', '%s');",
               new_credential, quoted_secret);
          g_free (quoted_secret);
        }

      sql ("INSERT INTO"
           " permissions (uuid, owner, name,"
           "              comment, resource_type, resource,"
           "              resource_uuid,"
           "              resource_location, subject_type, subject,"
           "              subject_location,"
           "              creation_time, modification_time)"
           " SELECT make_uuid(), owner, 'get_credentials',"
           "         'Autogenerated by Slave migration', 'credential', %llu,"
           "         (SELECT uuid FROM credentials_trash WHERE id=%llu),"
           "         " G_STRINGIFY (LOCATION_TRASH) ", subject_type, subject,"
           "         subject_location,"
           "         m_now (), m_now ()"
           " FROM permissions"
           " WHERE resource = %llu"
           "   AND resource_type = 'slave'"
           "   AND resource_location = " G_STRINGIFY (LOCATION_TRASH)
           " GROUP BY owner, subject_type, subject, subject_location;",
           new_credential, new_credential, slave);

      sql ("INSERT INTO"
           " permissions_trash (uuid, owner, name,"
           "                    comment, resource_type, resource,"
           "                    resource_uuid,"
           "                    resource_location, subject_type, subject,"
           "                    subject_location,"
           "                    creation_time, modification_time)"
           " SELECT make_uuid(), owner, 'get_credentials',"
           "         'Autogenerated by Slave migration', 'credential', %llu,"
           "         (SELECT uuid FROM credentials_trash WHERE id=%llu),"
           "         " G_STRINGIFY (LOCATION_TRASH) ", subject_type, subject,"
           "         subject_location,"
           "         m_now (), m_now ()"
           " FROM permissions_trash"
           " WHERE resource = %llu"
           "   AND resource_type = 'slave'"
           "   AND resource_location = " G_STRINGIFY (LOCATION_TRASH)
           " GROUP BY owner, subject_type, subject, subject_location;",
           new_credential, new_credential, slave);

      g_free (quoted_name);
      g_free (quoted_login);
    }
  cleanup_iterator (&slaves);

  /* Remove unused columns */
  if (sql_is_sqlite3 ())
    {
      sql ("ALTER TABLE slaves RENAME TO slaves_156;");
      sql ("ALTER TABLE slaves_trash RENAME TO slaves_trash_156;");

      sql ("CREATE TABLE IF NOT EXISTS slaves"
           " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment, host,"
           "  port, creation_time, modification_time, credential INTEGER);");
      sql ("CREATE TABLE IF NOT EXISTS slaves_trash"
           " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment, host,"
           "  port, creation_time, modification_time, credential INTEGER,"
           "  credential_location INTEGER);");

      sql ("INSERT INTO slaves"
           " (id, uuid, owner, name, comment, host, port,"
           "  creation_time, modification_time, credential)"
           " SELECT id, uuid, owner, name, comment, host, port,"
           "  creation_time, modification_time, credential"
           " FROM slaves_156;");
      sql ("INSERT INTO slaves_trash"
           " (id, uuid, owner, name, comment, host, port,"
           "  creation_time, modification_time, credential,"
           "  credential_location)"
           " SELECT id, uuid, owner, name, comment, host, port,"
           "  creation_time, modification_time, credential,"
           "  credential_location"
           " FROM slaves_trash_156;");

      sql ("DROP TABLE slaves_156;");
      sql ("DROP TABLE slaves_trash_156;");
    }
  else
    {
      sql ("ALTER TABLE slaves DROP COLUMN login;");
      sql ("ALTER TABLE slaves DROP COLUMN password;");
      sql ("ALTER TABLE slaves_trash DROP COLUMN login;");
      sql ("ALTER TABLE slaves_trash DROP COLUMN password;");
    }

  /* Set the database version to 157. */

  set_db_version (157);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 157 to version 158.
 *
 * @return 0 success, -1 error.
 */
int
migrate_157_to_158 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 157. */

  if (manage_db_version () != 157)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Add new column to configs tables. */
  if (sql_is_sqlite3 ())
    {
      sql ("ALTER TABLE configs ADD COLUMN scanner INTEGER;");
      sql ("ALTER TABLE configs_trash ADD COLUMN scanner INTEGER;");
    }
  else
    {
      sql ("ALTER TABLE configs ADD COLUMN scanner INTEGER"
           " REFERENCES scanners (id) ON DELETE RESTRICT;");
      sql ("ALTER TABLE configs_trash ADD COLUMN scanner INTEGER"
           " REFERENCES scanners (id) ON DELETE RESTRICT;");
    }

  /* Add first OSP scanner in scanners table, as scanner of OSP configs. */
  sql ("UPDATE configs"
       " SET scanner = (SELECT id FROM scanners WHERE type = %d LIMIT 1)"
       " WHERE type = 1;", SCANNER_TYPE_OSP);

  /* Set the database version to 158. */

  set_db_version (158);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 158 to version 159.
 *
 * @return 0 success, -1 error.
 */
int
migrate_158_to_159 ()
{
  iterator_t scanners;
  sql_begin_immediate ();

  /* Ensure that the database is currently version 158. */

  if (manage_db_version () != 158)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Add new columns to scanners tables. */
  if (sql_is_sqlite3 ())
    {
      sql ("ALTER TABLE scanners ADD COLUMN credential INTEGER;");
    }
  else
    {
      sql ("ALTER TABLE scanners ADD COLUMN credential INTEGER"
           " REFERENCES credentials (id) ON DELETE RESTRICT;");
    }
  sql ("ALTER TABLE scanners_trash ADD COLUMN credential INTEGER;");
  sql ("ALTER TABLE scanners_trash ADD COLUMN credential_location INTEGER;");

  /* Create new credentials */
  init_iterator (&scanners,
                 "SELECT id, name, key_pub, key_priv, owner FROM scanners;");

  while (next (&scanners))
    {
      scanner_t scanner;
      const char *name, *key_pub, *key_priv;
      user_t owner;
      credential_t new_credential;
      gchar *quoted_name, *quoted_key_pub;

      scanner = iterator_int64 (&scanners, 0);
      name = iterator_string (&scanners, 1);
      key_pub = iterator_string (&scanners, 2);
      key_priv = iterator_string (&scanners, 3);
      owner = iterator_int64 (&scanners, 4);

      // Skip if scanner has no key (internal CVE scanner)
      if (key_pub == NULL || key_priv == NULL)
        continue;

      quoted_name = sql_quote (name);
      quoted_key_pub = sql_quote (key_pub);

      if (owner)
        {
          if (sql_int ("SELECT count(*) FROM credentials"
                      " WHERE name = 'Credential for Scanner %s'"
                      "   AND owner = %llu;",
                      quoted_name, owner))
            sql ("INSERT INTO credentials"
                 " (uuid, name, owner, comment, type,"
                 "  creation_time, modification_time)"
                 " VALUES"
                 " (make_uuid (),"
                 "  uniquify ('credential',"
                 "            'Credential for Scanner %s', %llu, ''),"
                 "  %llu, 'Autogenerated by migration', 'cc',"
                 "  m_now (), m_now ());",
                 quoted_name, owner, owner);
          else
            sql ("INSERT INTO credentials"
                 " (uuid, name, owner, comment, type,"
                 "  creation_time, modification_time)"
                 " VALUES"
                 " (make_uuid (), 'Credential for Scanner %s',"
                 "  %llu, 'Autogenerated by migration', 'cc',"
                 "  m_now (), m_now ());",
                 quoted_name, owner);
        }
      else
        {
          if (sql_int ("SELECT count(*) FROM credentials"
                      " WHERE name = 'Credential for Scanner %s'"
                      "   AND owner = NULL;",
                      quoted_name, owner))
            sql ("INSERT INTO credentials"
                 " (uuid, name, owner, comment, type,"
                 "  creation_time, modification_time)"
                 " VALUES"
                 " (make_uuid (),"
                 "  uniquify ('credential',"
                 "            'Credential for Scanner %s', NULL, ''),"
                 "  NULL, 'Autogenerated by migration', 'cc',"
                 "  m_now (), m_now ());",
                 quoted_name);
          else
            sql ("INSERT INTO credentials"
                 " (uuid, name, owner, comment, type,"
                 "  creation_time, modification_time)"
                 " VALUES"
                 " (make_uuid (), 'Credential for Scanner %s',"
                 "  NULL, 'Autogenerated by migration', 'cc',"
                 "  m_now (), m_now ());",
                 quoted_name);
        }

      new_credential = sql_last_insert_id ();

      sql ("UPDATE scanners SET credential = %llu WHERE id = %llu;",
           new_credential, scanner);

      sql ("INSERT INTO credentials_data (credential, type, value)"
           " VALUES (%llu, 'certificate', '%s');",
           new_credential, quoted_key_pub);

      if (disable_encrypted_credentials)
        {
          gchar *quoted_key_priv;
          quoted_key_priv = sql_quote (key_priv);
          sql ("INSERT INTO credentials_data (credential, type, value)"
               " VALUES (%llu, 'private_key', '%s');",
               new_credential, quoted_key_priv);
          g_free (quoted_key_priv);
        }
      else
        {
          char *secret;
          gchar *quoted_secret;

          if (!scanners.crypt_ctx)
            scanners.crypt_ctx = lsc_crypt_new ();

          secret = lsc_crypt_encrypt (scanners.crypt_ctx,
                                      "private_key", key_priv, NULL);
          if (!secret)
            {
              g_free (quoted_name);
              g_free (quoted_key_pub);
              cleanup_iterator (&scanners);
              sql_rollback ();
              return -1;
            }
          quoted_secret = sql_quote (secret);
          sql ("INSERT INTO credentials_data (credential, type, value)"
               " VALUES (%llu, 'secret', '%s');",
              new_credential, quoted_secret);
          g_free (quoted_secret);
        }

      sql ("INSERT INTO"
           " permissions (uuid, owner, name,"
           "              comment, resource_type, resource,"
           "              resource_uuid,"
           "              resource_location, subject_type, subject,"
           "              subject_location, creation_time, modification_time)"
           " SELECT make_uuid(), owner, 'get_credentials',"
           "         'Autogenerated by Scanner migration', 'credential', %llu,"
           "         (SELECT uuid FROM credentials WHERE id=%llu),"
           "         " G_STRINGIFY (LOCATION_TABLE) ", subject_type, subject,"
           "         subject_location, m_now (), m_now ()"
           " FROM permissions"
           " WHERE resource = %llu"
           "   AND resource_type = 'scanner'"
           "   AND resource_location = " G_STRINGIFY (LOCATION_TABLE)
           " GROUP BY owner, subject_type, subject, subject_location;",
           new_credential, new_credential, scanner);

      sql ("INSERT INTO"
           " permissions_trash (uuid, owner, name,"
           "                    comment, resource_type, resource,"
           "                    resource_uuid,"
           "                    resource_location, subject_type, subject,"
           "                    subject_location,"
           "                    creation_time, modification_time)"
           " SELECT make_uuid(), owner, 'get_credentials',"
           "         'Autogenerated by Scanner migration', 'credential', %llu,"
           "         (SELECT uuid FROM credentials WHERE id=%llu),"
           "         " G_STRINGIFY (LOCATION_TABLE) ", subject_type, subject,"
           "         subject_location, m_now (), m_now ()"
           " FROM permissions_trash"
           " WHERE resource = %llu"
           "   AND resource_type = 'scanner'"
           "   AND resource_location = " G_STRINGIFY (LOCATION_TABLE)
           " GROUP BY owner, subject_type, subject, subject_location;",
           new_credential, new_credential, scanner);

      g_free (quoted_name);
      g_free (quoted_key_pub);
    }
  cleanup_iterator (&scanners);

  /* Create new credentials for trashcan. */
  init_iterator (&scanners,
                 "SELECT id, name, key_pub, key_priv, owner"
                 " FROM scanners_trash;");

  while (next (&scanners))
    {
      scanner_t scanner;
      const char *name, *key_pub, *key_priv;
      user_t owner;
      credential_t new_credential;
      gchar *quoted_name, *quoted_key_pub;

      scanner = iterator_int64 (&scanners, 0);
      name = iterator_string (&scanners, 1);
      key_pub = iterator_string (&scanners, 2);
      key_priv = iterator_string (&scanners, 3);
      owner = iterator_int64 (&scanners, 4);

      /* Skip if scanner has no key (internal CVE scanner). */
      if (key_pub == NULL || key_priv == NULL)
        continue;

      quoted_name = sql_quote (name);
      quoted_key_pub = sql_quote (key_pub);

      if (owner)
        sql ("INSERT INTO credentials_trash"
             " (uuid, name, owner, comment, type,"
             "  creation_time, modification_time)"
             " VALUES"
             " (make_uuid (), 'Credential for Scanner %s',"
             "  %llu, 'Autogenerated by migration', 'cc',"
             "  m_now (), m_now ());",
             quoted_name, owner);
      else
        sql ("INSERT INTO credentials_trash"
             " (uuid, name, owner, comment, type,"
             "  creation_time, modification_time)"
             " VALUES"
             " (make_uuid (), 'Credential for Scanner %s',"
             "  NULL, 'Autogenerated by migration', 'cc',"
             "  m_now (), m_now ());",
             quoted_name);

      new_credential = sql_last_insert_id ();

      sql ("UPDATE scanners_trash SET credential = %llu,"
           " credential_location = " G_STRINGIFY (LOCATION_TRASH)
           " WHERE id = %llu;",
           new_credential, scanner);

      sql ("INSERT INTO credentials_trash_data (credential, type, value)"
           " VALUES (%llu, 'certificate', '%s');",
           new_credential, quoted_key_pub);

      if (disable_encrypted_credentials)
        {
          gchar *quoted_key_priv;
          quoted_key_priv = sql_quote (key_priv);
          sql ("INSERT INTO credentials_trash_data (credential, type, value)"
               " VALUES (%llu, 'private_key', '%s');",
               new_credential, quoted_key_priv);
          g_free (quoted_key_priv);
        }
      else
        {
          char *secret;
          gchar *quoted_secret;

          if (!scanners.crypt_ctx)
            scanners.crypt_ctx = lsc_crypt_new ();

          secret = lsc_crypt_encrypt (scanners.crypt_ctx,
                                      "private_key", key_priv, NULL);
          if (!secret)
            {
              g_free (quoted_name);
              g_free (quoted_key_pub);
              cleanup_iterator (&scanners);
              sql_rollback ();
              return -1;
            }
          quoted_secret = sql_quote (secret);
          sql ("INSERT INTO credentials_trash_data (credential, type, value)"
               " VALUES (%llu, 'secret', '%s');",
               new_credential, quoted_secret);
          g_free (quoted_secret);
        }

      sql ("INSERT INTO"
           " permissions (uuid, owner, name,"
           "              comment, resource_type, resource,"
           "              resource_uuid,"
           "              resource_location, subject_type, subject,"
           "              subject_location,"
           "              creation_time, modification_time)"
           " SELECT make_uuid(), owner, 'get_credentials',"
           "         'Autogenerated by Scanner migration', 'credential', %llu,"
           "         (SELECT uuid FROM credentials_trash WHERE id=%llu),"
           "         " G_STRINGIFY (LOCATION_TRASH) ", subject_type, subject,"
           "         subject_location,"
           "         m_now (), m_now ()"
           " FROM permissions"
           " WHERE resource = %llu"
           "   AND resource_type = 'scanner'"
           "   AND resource_location = " G_STRINGIFY (LOCATION_TRASH)
           " GROUP BY owner, subject_type, subject, subject_location;",
           new_credential, new_credential, scanner);

      sql ("INSERT INTO"
           " permissions_trash (uuid, owner, name,"
           "                    comment, resource_type, resource,"
           "                    resource_uuid,"
           "                    resource_location, subject_type, subject,"
           "                    subject_location,"
           "                    creation_time, modification_time)"
           " SELECT make_uuid(), owner, 'get_credentials',"
           "         'Autogenerated by Scanner migration', 'credential', %llu,"
           "         (SELECT uuid FROM credentials_trash WHERE id=%llu),"
           "         " G_STRINGIFY (LOCATION_TRASH) ", subject_type, subject,"
           "         subject_location,"
           "         m_now (), m_now ()"
           " FROM permissions_trash"
           " WHERE resource = %llu"
           "   AND resource_type = 'scanner'"
           "   AND resource_location = " G_STRINGIFY (LOCATION_TRASH)
           " GROUP BY owner, subject_type, subject, subject_location;",
           new_credential, new_credential, scanner);

      g_free (quoted_name);
      g_free (quoted_key_pub);
    }
  cleanup_iterator (&scanners);

  /* Remove unused columns. */
  if (sql_is_sqlite3 ())
    {
      sql ("ALTER TABLE scanners RENAME TO scanners_158;");
      sql ("ALTER TABLE scanners_trash RENAME TO scanners_trash_158;");

      sql ("CREATE TABLE IF NOT EXISTS scanners"
          " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment,"
          "  host, port, type, ca_pub, credential INTEGER,"
          "  creation_time, modification_time);");
      sql ("CREATE TABLE IF NOT EXISTS scanners_trash"
          " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment,"
          "  host, port, type, ca_pub, credential INTEGER,"
          "  credential_location INTEGER, creation_time, modification_time);");

      sql ("INSERT INTO scanners"
           " (id, uuid, owner, name, comment, host, port, type,"
           "  ca_pub, credential, creation_time, modification_time)"
           " SELECT id, uuid, owner, name, comment, host, port, type,"
           "  ca_pub, credential, creation_time, modification_time"
           " FROM scanners_158;");
      sql ("INSERT INTO scanners_trash"
           " (id, uuid, owner, name, comment, host, port, type,"
           "  ca_pub, credential, credential_location, creation_time,"
           "  modification_time)"
           " SELECT id, uuid, owner, name, comment, host, port, type,"
           "  ca_pub, credential, credential_location, creation_time,"
           "  modification_time"
           " FROM scanners_trash_158;");

      sql ("DROP TABLE scanners_158;");
      sql ("DROP TABLE scanners_trash_158;");
    }
  else
    {
      sql ("ALTER TABLE scanners DROP COLUMN key_pub;");
      sql ("ALTER TABLE scanners DROP COLUMN key_priv;");
      sql ("ALTER TABLE scanners_trash DROP COLUMN key_pub;");
      sql ("ALTER TABLE scanners_trash DROP COLUMN key_priv;");
    }

  /* Set the database version to 159. */

  set_db_version (159);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 159 to version 160.
 *
 * @return 0 success, -1 error.
 */
int
migrate_159_to_160 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 159. */

  if (manage_db_version () != 159)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Report format "Verinice ISM" was missing a param. */

  sql ("INSERT INTO report_format_params (report_format, name, type, value,"
       " type_min, type_max, type_regex, fallback)"
       " VALUES ((SELECT id FROM report_formats"
       "          WHERE uuid = 'c15ad349-bd8d-457a-880a-c7056532ee15'),"
       "         'Attach HTML report', %i, 1, 0, 1, '', 1);",
       REPORT_FORMAT_PARAM_TYPE_BOOLEAN);

  /* Set the database version to 160. */

  set_db_version (160);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 160 to version 161.
 *
 * @return 0 success, -1 error.
 */
int
migrate_160_to_161 ()
{
  iterator_t iter;
  iter.crypt_ctx = NULL;

  sql_begin_immediate ();

  /* Ensure that the database is currently version 160. */

  if (manage_db_version () != 160)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Create copies of SSH key credentials that are used in place of
   * username + password ones. */
  init_iterator (&iter,
                 "SELECT 0, id, name, owner,"
                 " (SELECT value FROM credentials_data"
                 "  WHERE credential = credentials.id"
                 "    AND type = 'secret'),"
                 " (SELECT value FROM credentials_data"
                 "  WHERE credential = credentials.id"
                 "    AND type = 'password')"
                 " FROM credentials"
                 " WHERE type = 'usk'"
                 "   AND (id IN (SELECT credential"
                 "               FROM targets_login_data"
                 "               WHERE type='smb' OR type='esxi')"
                 "        OR id IN (SELECT credential"
                 "                  FROM targets_trash_login_data"
                 "                  WHERE (type='smb' OR type='esxi')"
                 "                    AND credential_location"
                 "                        = " G_STRINGIFY (LOCATION_TABLE) "))"
                 " UNION ALL"
                 " SELECT 1, id, name, owner,"
                 " (SELECT value FROM credentials_trash_data"
                 "  WHERE credential = credentials_trash.id"
                 "    AND type = 'secret'),"
                 " (SELECT value FROM credentials_trash_data"
                 "  WHERE credential = credentials_trash.id"
                 "    AND type = 'password')"
                 " FROM credentials_trash"
                 "  WHERE type = 'usk'"
                 "    AND id IN (SELECT credential"
                 "               FROM targets_trash_login_data"
                 "               WHERE (type='smb' OR type='esxi')"
                 "                 AND credential_location"
                 "                     = " G_STRINGIFY (LOCATION_TRASH) ");");

  while (next (&iter))
    {
      int trash;
      credential_t credential, new_credential;
      const char *name, *old_secret, *old_password;
      gchar* quoted_name;
      user_t owner;

      trash = iterator_int (&iter, 0);
      credential = iterator_int64 (&iter, 1);
      name = iterator_string (&iter, 2);
      quoted_name = sql_quote (name);
      owner = iterator_int64 (&iter, 3);
      old_secret = iterator_string (&iter, 4);

      // Copy credential base
      if (trash)
        {
          sql ("INSERT INTO credentials_trash"
               " (uuid, name, owner, comment, type,"
               "  creation_time, modification_time)"
               " VALUES"
               " (make_uuid (), '%s - user and password',"
               "  %llu, 'Autogenerated by migration', 'up',"
               "  m_now (), m_now ());",
               quoted_name, owner);
        }
      else
        {
          if (sql_int ("SELECT count(*) FROM credentials"
                      " WHERE name = '%s - user and password'"
                      "   AND owner = %llu;",
                      quoted_name, owner))
            sql ("INSERT INTO credentials"
                " (uuid, name, owner, comment, type,"
                "  creation_time, modification_time)"
                " VALUES"
                " (make_uuid (),"
                "  uniquify ('credential', '%s - user and password', %llu, ''),"
                "  %llu, 'Autogenerated by migration', 'up',"
                "  m_now (), m_now ());",
                quoted_name, owner, owner);
          else
            sql ("INSERT INTO credentials"
                " (uuid, name, owner, comment, type,"
                "  creation_time, modification_time)"
                " VALUES"
                " (make_uuid (), '%s - user and password',"
                "  %llu, 'Autogenerated by migration', 'up',"
                "  m_now (), m_now ());",
                quoted_name, owner);
        }

      new_credential = sql_last_insert_id ();

      // Copy username
      sql ("INSERT INTO %s (credential, type, value)"
           " SELECT %llu, 'username', value FROM %s"
           "  WHERE credential = %llu AND type = 'username'",
           trash ? "credentials_trash_data" : "credentials_data",
           new_credential,
           trash ? "credentials_trash_data" : "credentials_data",
           credential);

      // Copy password
      if (iter.crypt_ctx == NULL)
        iter.crypt_ctx = lsc_crypt_new ();

      if (old_secret)
        old_password = lsc_crypt_get_password (iter.crypt_ctx, old_secret);
      else
        old_password = iterator_string (&iter, 5);

      if (disable_encrypted_credentials)
        {
          gchar *quoted_password = sql_quote (old_password ? old_password : "");
          sql ("INSERT INTO %s (credential, type, value)"
               " VALUES (%llu, 'password', '%s');",
               trash ? "credentials_trash_data" : "credentials_data",
               new_credential,
               quoted_password);
          g_free (quoted_password);
        }
      else
        {
          lsc_crypt_ctx_t encrypt_ctx = lsc_crypt_new ();
          gchar *new_secret = lsc_crypt_encrypt (encrypt_ctx,
                                                 "password", old_password,
                                                 NULL);
          sql ("INSERT INTO %s (credential, type, value)"
               " VALUES (%llu, 'password', '%s');",
               trash ? "credentials_trash_data" : "credentials_data",
               new_credential,
               new_secret);
          lsc_crypt_release (encrypt_ctx);
          g_free (new_secret);
        }

      // Update targets
      if (trash)
        {
          sql ("UPDATE targets_trash_login_data SET credential = %llu"
               " WHERE credential = %llu"
               " AND (type = 'smb' OR type = 'esxi')"
               " AND credential_location = " G_STRINGIFY (LOCATION_TRASH) ";",
               new_credential, credential);
        }
      else
        {
          sql ("UPDATE targets_login_data SET credential = %llu"
               " WHERE credential = %llu"
               "   AND (type = 'smb' OR type = 'esxi');",
               new_credential, credential);
          sql ("UPDATE targets_trash_login_data SET credential = %llu"
               " WHERE credential = %llu"
               " AND (type = 'smb' OR type = 'esxi')"
               " AND credential_location = " G_STRINGIFY (LOCATION_TABLE) ";",
               new_credential, credential);
        }

    }
  cleanup_iterator(&iter);

  /* Set the database version to 161. */

  set_db_version (161);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 161 to version 162.
 *
 * @return 0 success, -1 error.
 */
int
migrate_161_to_162 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 161. */

  if (manage_db_version () != 161)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Add allow_insecure column to credentials and credentials_trash */
  sql ("ALTER TABLE credentials ADD COLUMN allow_insecure INTEGER;");
  sql ("ALTER TABLE credentials_trash ADD COLUMN allow_insecure INTEGER;");

  /* Set the value of the new column */
  sql ("UPDATE credentials SET allow_insecure = 0;");
  sql ("UPDATE credentials_trash SET allow_insecure = 0;");

  /* Set the database version to 162. */

  set_db_version (162);

  sql_commit ();

  return 0;
}

/**
 * @brief Description for Verinice ISM report format.
 */
#define MIGRATE_162_TO_163_CONTROL_DESCRIPTION                                  \
 "Dear IS Coordinator,\n"                                                       \
 "\n"                                                                           \
 "A new scan has been carried out and the results are now available in Verinice.\n"        \
 "If responsible persons are linked to the asset groups, the tasks are already created.\n" \
 "\n"                                                                           \
 "Please check the results in a timely manner.\n"                               \
 "\n"                                                                           \
 "Best regards\n"                                                               \
 "CIS"

/**
 * @brief Migrate the database from version 158 to version 162.
 *
 * @return 0 success, -1 error.
 */
int
migrate_162_to_163 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 162. */

  if (manage_db_version () != 162)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Report format "Verinice ISM" got a new param. */

  sql ("INSERT INTO report_format_params (report_format, name, type, value,"
       " type_min, type_max, type_regex, fallback)"
       " VALUES ((SELECT id FROM report_formats"
       "          WHERE uuid = 'c15ad349-bd8d-457a-880a-c7056532ee15'),"
       "         'ISM Control Description', %i, '%s', 0, 100000, '', '%s');",
       REPORT_FORMAT_PARAM_TYPE_TEXT,
       MIGRATE_162_TO_163_CONTROL_DESCRIPTION,
       MIGRATE_162_TO_163_CONTROL_DESCRIPTION);

  /* Set the database version to 163. */

  set_db_version (163);

  sql_commit ();

  return 0;
}

/**
 * @brief Chart SQL for migrate_163_to_164.
 *
 * @param[in]  type        Type.
 * @param[in]  default     Default
 * @param[in]  left_uuid   Left UUID.
 * @param[in]  right_uuid  Left UUID.
 */
#define UPDATE_CHART_SETTINGS(type, default, left_uuid, right_uuid)          \
  sql ("INSERT INTO settings (owner, uuid, name, value)"                     \
       " SELECT owner, '%s', 'Dummy', 'left-' || '%s' FROM settings"         \
       " WHERE uuid = '%s'"                                                  \
       " AND NOT EXISTS (SELECT * FROM settings AS old_settings"             \
       "                 WHERE old_settings.uuid = '%s'"                     \
       "                   AND old_settings.owner = settings.owner);",       \
       left_uuid, default, right_uuid, left_uuid);                           \
  sql ("UPDATE settings"                                                     \
       " SET name = '%s Top Dashboard Components',"                          \
       "     value = coalesce ((SELECT substr (old_settings.value, 6)"       \
       "                        FROM settings AS old_settings"               \
       "                        WHERE old_settings.uuid = '%s'"              \
       "                          AND old_settings.owner = settings.owner)," \
       "                       '" default "')"                               \
       "             || '|'"                                                 \
       "             || coalesce ((SELECT substr (old_settings.value, 7)"    \
       "                           FROM settings AS old_settings"            \
       "                           WHERE old_settings.uuid = '%s'"           \
       "                           AND old_settings.owner = settings.owner),"\
       "                          '" default "')"                            \
       " WHERE uuid = '%s';",                                                \
       type, left_uuid, right_uuid, left_uuid);                              \
  sql ("DELETE FROM settings"                                                \
       " WHERE uuid = '%s';",                                                \
       right_uuid);

/**
 * @brief Dashboard SQL for migrate_163_to_164.
 */
#define UPDATE_DASHBOARD_SETTINGS(type, default,                             \
                                  uuid_1, uuid_2, uuid_3, uuid_4,            \
                                  filter_1, filter_2, filter_3, filter_4)    \
  sql ("INSERT INTO settings (owner, uuid, name, value)"                     \
       " SELECT DISTINCT owner, '%s', 'dummy', '%s' FROM settings"           \
       " WHERE uuid IN ('%s', '%s', '%s')"                                   \
       " AND NOT EXISTS (SELECT * FROM settings AS old_settings"             \
       "                 WHERE uuid = '%s'"                                  \
       "                   AND old_settings.owner = settings.owner);",       \
       uuid_1, default, uuid_2, uuid_3, uuid_4, uuid_1);                     \
  sql ("UPDATE settings"                                                     \
       " SET name = '%s Dashboard Components',"                              \
       "     value = coalesce ((SELECT substr (old_settings.value,"          \
       "                                      length ('" type "') + 4)"      \
       "                       FROM settings AS old_settings"                \
       "                       WHERE old_settings.uuid = '%s'"               \
       "                       AND old_settings.owner = settings.owner),"    \
       "                       '" default "')"                               \
       "             || '|'"                                                 \
       "             || coalesce ((SELECT substr (old_settings.value,"       \
       "                                          length ('" type "') + 4)"  \
       "                           FROM settings AS old_settings"            \
       "                           WHERE old_settings.uuid = '%s'"           \
       "                           AND old_settings.owner = settings.owner),"\
       "                          '" default "')"                            \
       "             || '#'"                                                 \
       "             || coalesce ((SELECT substr (old_settings.value,"       \
       "                                          length ('" type "') + 4)"  \
       "                           FROM settings AS old_settings"            \
       "                           WHERE old_settings.uuid = '%s'"           \
       "                           AND old_settings.owner = settings.owner),"\
       "                          '" default "')"                            \
       "             || '|'"                                                 \
       "             || coalesce ((SELECT substr (old_settings.value,"       \
       "                                          length ('" type "') + 4)"  \
       "                           FROM settings AS old_settings"            \
       "                           WHERE old_settings.uuid = '%s'"           \
       "                           AND old_settings.owner = settings.owner),"\
       "                          '" default "')"                            \
       " WHERE uuid = '%s';",                                                \
       type, uuid_1, uuid_2, uuid_3, uuid_4, uuid_1);                        \
  sql ("INSERT INTO settings (owner, uuid, name, value)"                     \
       " SELECT DISTINCT owner, '%s', 'dummy', '' FROM settings"             \
       " WHERE uuid IN ('%s', '%s', '%s')"                                   \
       " AND NOT EXISTS (SELECT * FROM settings AS old_settings"             \
       "                 WHERE uuid = '%s'"                                  \
       "                   AND old_settings.owner = settings.owner);",       \
       filter_1, filter_2, filter_3, filter_4, filter_1);                    \
  sql ("UPDATE settings"                                                     \
       " SET name = '%s Dashboard Filters',"                                 \
       "     value = coalesce ((SELECT old_settings.value"                   \
       "                        FROM settings AS old_settings"               \
       "                        WHERE old_settings.uuid = '%s'"              \
       "                        AND old_settings.owner = settings.owner),"   \
       "                       '')"                                          \
       "             || '|'"                                                 \
       "             || coalesce ((SELECT old_settings.value"                \
       "                           FROM settings AS old_settings"            \
       "                           WHERE old_settings.uuid = '%s'"           \
       "                           AND old_settings.owner = settings.owner),"\
       "                          '')"                                       \
       "             || '#'"                                                 \
       "             || coalesce ((SELECT old_settings.value"                \
       "                           FROM settings AS old_settings"            \
       "                           WHERE old_settings.uuid = '%s'"           \
       "                           AND old_settings.owner = settings.owner),"\
       "                          '')"                                       \
       "             || '|'"                                                 \
       "             || coalesce ((SELECT old_settings.value"                \
       "                           FROM settings AS old_settings"            \
       "                           WHERE old_settings.uuid = '%s'"           \
       "                           AND old_settings.owner = settings.owner),"\
       "                          '')"                                       \
       " WHERE uuid = '%s';",                                                \
       type, filter_1, filter_2, filter_3, filter_4, filter_1);              \
  sql ("DELETE FROM settings"                                                \
       " WHERE uuid IN ('%s', '%s', '%s', '%s', '%s', '%s');",               \
       uuid_2, uuid_3, uuid_4, filter_2, filter_3, filter_4);

/**
 * @brief Migrate the database from version 163 to version 164.
 *
 * @return 0 success, -1 error.
 */
int
migrate_163_to_164 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 163. */

  if (manage_db_version () != 163)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Remove duplicate settings */
  sql ("DELETE FROM settings"
       " WHERE id NOT IN (SELECT min(id) FROM settings"
       "                   GROUP BY uuid, owner);");

  /* Change top chart settings to new format */
  UPDATE_CHART_SETTINGS ("Tasks", "by-cvss",
                         "3d5db3c7-5208-4b47-8c28-48efc621b1e0",
                         "ce8608af-7e66-45a8-aa8a-76def4f9f838")
  UPDATE_CHART_SETTINGS ("Reports", "by-cvss",
                         "e599bb6b-b95a-4bb2-a6bb-fe8ac69bc071",
                         "fc875cd4-16bf-42d1-98ed-c0c9bd6015cd")
  UPDATE_CHART_SETTINGS ("Results", "by-cvss",
                         "0b8ae70d-d8fc-4418-8a72-e65ac8d2828e",
                         "cb7db2fe-3fe4-4704-9fa1-efd4b9e522a8")

  UPDATE_CHART_SETTINGS ("NVTs", "by-cvss",
                         "f68d9369-1945-477b-968f-121c6029971b",
                         "af89a84a-d3ec-43a8-97a8-aa688bf093bc")
  UPDATE_CHART_SETTINGS ("CVEs", "by-cvss",
                         "815ddd2e-8654-46c7-a05b-d73224102240",
                         "418a5746-d68a-4a2d-864a-0da993b32220")
  UPDATE_CHART_SETTINGS ("CPEs", "by-cvss",
                         "9cff9b4d-b164-43ce-8687-f2360afc7500",
                         "629fdb73-35fa-4247-9018-338c202f7c03")
  UPDATE_CHART_SETTINGS ("OVAL Definitions", "by-cvss",
                         "9563efc0-9f4e-4d1f-8f8d-0205e32b90a4",
                         "fe1610a3-4e87-4b0d-9b7a-f0f66fef586b")
  UPDATE_CHART_SETTINGS ("CERT Bund Advisories", "by-cvss",
                         "a6946f44-480f-4f37-8a73-28a4cd5310c4",
                         "469d50da-880a-4bfc-88ed-22e53764c683")
  UPDATE_CHART_SETTINGS ("DFN CERT Advisories", "by-cvss",
                         "9812ea49-682d-4f99-b3cc-eca051d1ce59",
                         "72014b52-4389-435d-9438-8c13601ecbd2")
  UPDATE_CHART_SETTINGS ("All SecInfo", "by-cvss",
                         "4c7b1ea7-b7e6-4d12-9791-eb9f72b6f864",
                         "985f38eb-1a30-4a35-abb6-3eec05b5d54a")

  /* Update standalone dashboard */
  UPDATE_DASHBOARD_SETTINGS ("SecInfo", "nvts-by-cvss",
                             "84ab32da-fe69-44d8-8a8f-70034cf28d4e",
                             "42d48049-3153-43bf-b30d-72ca5ab1eb49",
                             "76f34fe0-254a-4481-97aa-c6f1da2f842b",
                             "71106ed7-b677-414e-bf67-2e7716441db3",
                             "517d0efe-426e-49a9-baa7-eda2832c93e8",
                             "3c693fb2-4f87-4b1f-a09e-cb9aa66440f4",
                             "bffa72a5-8110-49f9-aa5e-f431ce834826",
                             "268079c6-f353-414f-9b7c-43f5419edf2d")

  /* Set the database version to 164. */

  set_db_version (164);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 163 to version 164.
 *
 * @return 0 success, -1 error.
 */
int
migrate_164_to_165 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 164. */

  if (manage_db_version () != 164)
    {
      sql_rollback ();
      return -1;
    }

  /* Update database */

  /* Add hr_name column to config_preferences table
   * and initialize it with name for OSP results. */
  sql ("ALTER TABLE config_preferences ADD COLUMN hr_name TEXT;");
  sql ("UPDATE config_preferences"
       " SET hr_name = name"
       " WHERE type != 'SERVER_PREFS' AND type != 'PLUGINS_PREFS';");

  /* Add hr_name column to config_preferences_trash table
   * and initialize it with name for OSP results. */
  sql ("ALTER TABLE config_preferences_trash ADD COLUMN hr_name TEXT;");
  sql ("UPDATE config_preferences_trash"
       " SET hr_name = name"
       " WHERE type != 'SERVER_PREFS' AND type != 'PLUGINS_PREFS';");

  /* Set the database version to 165. */

  set_db_version (165);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 165 to version 166.
 *
 * @return 0 success, -1 error.
 */
int
migrate_165_to_166 ()
{
  iterator_t alert_data;
  sql_begin_immediate ();

  /* Ensure that the database is currently version 165. */

  if (manage_db_version () != 165)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Create new credentials. */
  init_iterator (&alert_data,
                 "SELECT id, name,"
                 "       (SELECT data FROM alert_method_data"
                 "        WHERE alert = alerts.id"
                 "          AND (name='scp_username'"
                 "               OR name='verinice_server_username')),"
                 "       (SELECT data FROM alert_method_data"
                 "        WHERE alert = alerts.id"
                 "          AND (name='scp_password'"
                 "               OR name='verinice_server_password')),"
                 "       owner, method"
                 " FROM alerts WHERE method = 8 OR method = 6;");

  while (next (&alert_data))
    {
      alert_t alert;
      const char *name, *login, *password;
      user_t owner;
      credential_t new_credential;
      gchar *new_credential_id, *quoted_name, *quoted_login;
      int method;

      alert = iterator_int64 (&alert_data, 0);
      name = iterator_string (&alert_data, 1);
      login = iterator_string (&alert_data, 2);
      password = iterator_string (&alert_data, 3);
      owner = iterator_int64 (&alert_data, 4);
      method = iterator_int (&alert_data, 5);

      /* Skip the alert if it is missing login info. */
      if (name == NULL || password == NULL)
        continue;

      quoted_name = sql_quote (name);
      quoted_login = sql_quote (login);

      /* Create basic credential. */
      if (sql_int ("SELECT count(*) FROM credentials"
                   " WHERE name = 'Credential for Alert %s'"
                   "   AND owner = %llu;",
                   quoted_name, owner))
        sql ("INSERT INTO credentials"
             " (uuid, name, owner, comment, type,"
             "  creation_time, modification_time)"
             " VALUES"
             " (make_uuid (),"
             "  uniquify ('credential', 'Credential for Alert %s', %llu, ''),"
             "  %llu, 'Autogenerated by migration', 'up',"
             "  m_now (), m_now ());",
             quoted_name, owner, owner);
      else
        sql ("INSERT INTO credentials"
             " (uuid, name, owner, comment, type,"
             "  creation_time, modification_time)"
             " VALUES"
             " (make_uuid (), 'Credential for Alert %s',"
             "  %llu, 'Autogenerated by migration', 'up',"
             "  m_now (), m_now ());",
             quoted_name, owner);

      /* Add credential data. */
      new_credential = sql_last_insert_id ();
      new_credential_id = sql_string ("SELECT uuid FROM credentials"
                                      " WHERE id = %llu;",
                                      new_credential);

      sql ("INSERT INTO credentials_data (credential, type, value)"
           " VALUES (%llu, 'username', '%s');",
           new_credential,
           quoted_login);

      if (disable_encrypted_credentials)
        {
          gchar *quoted_password;
          quoted_password = sql_quote (password);
          sql ("INSERT INTO credentials_data (credential, type, value)"
               " VALUES (%llu, 'password', '%s');",
               new_credential, quoted_password);
          g_free (quoted_password);
        }
      else
        {
          char *secret;
          gchar *quoted_secret;

          if (!alert_data.crypt_ctx)
            alert_data.crypt_ctx = lsc_crypt_new ();

          secret = lsc_crypt_encrypt (alert_data.crypt_ctx,
                                      "password", password, NULL);
          if (!secret)
            {
              g_free (quoted_name);
              g_free (quoted_login);
              cleanup_iterator (&alert_data);
              sql_rollback ();
              return -1;
            }
          quoted_secret = sql_quote (secret);
          sql ("INSERT INTO credentials_data (credential, type, value)"
               " VALUES (%llu, 'secret', '%s');",
              new_credential, quoted_secret);
          g_free (quoted_secret);
        }

      /* Update alert_method_data. */
      sql ("INSERT INTO alert_method_data (alert, name, data)"
           " VALUES (%llu, '%s_credential', '%s');",
           alert,
           method == 8 ? "scp" : "verinice_server",
           new_credential_id);

      /* Create permissions. */
      sql ("INSERT INTO"
           " permissions (uuid, owner, name,"
           "              comment, resource_type, resource,"
           "              resource_uuid,"
           "              resource_location, subject_type, subject,"
           "              subject_location, creation_time, modification_time)"
           " SELECT make_uuid(), owner, 'get_credentials',"
           "         'Autogenerated by Alert migration', 'credential', %llu,"
           "         (SELECT uuid FROM credentials WHERE id=%llu),"
           "         " G_STRINGIFY (LOCATION_TABLE) ", subject_type, subject,"
           "         subject_location, m_now (), m_now ()"
           " FROM permissions"
           " WHERE resource = %llu"
           "   AND resource_type = 'alert'"
           "   AND resource_location = " G_STRINGIFY (LOCATION_TABLE)
           " GROUP BY owner, subject_type, subject, subject_location;",
           new_credential, new_credential, alert);

      sql ("INSERT INTO"
           " permissions_trash (uuid, owner, name,"
           "                    comment, resource_type, resource,"
           "                    resource_uuid,"
           "                    resource_location, subject_type, subject,"
           "                    subject_location,"
           "                    creation_time, modification_time)"
           " SELECT make_uuid(), owner, 'get_credentials',"
           "         'Autogenerated by Alert migration', 'credential', %llu,"
           "         (SELECT uuid FROM credentials WHERE id=%llu),"
           "         " G_STRINGIFY (LOCATION_TABLE) ", subject_type, subject,"
           "         subject_location, m_now (), m_now ()"
           " FROM permissions_trash"
           " WHERE resource = %llu"
           "   AND resource_type = 'alert'"
           "   AND resource_location = " G_STRINGIFY (LOCATION_TABLE)
           " GROUP BY owner, subject_type, subject, subject_location;",
           new_credential, new_credential, alert);

      g_free (new_credential_id);
      g_free (quoted_name);
      g_free (quoted_login);
    }
  cleanup_iterator (&alert_data);

  /* Create new trash credentials. */
  init_iterator (&alert_data,
                 "SELECT id, name,"
                 "       (SELECT data FROM alert_method_data_trash"
                 "        WHERE alert = alerts_trash.id"
                 "          AND (name='scp_username'"
                 "               OR name='verinice_server_username')),"
                 "       (SELECT data FROM alert_method_data_trash"
                 "        WHERE alert = alerts_trash.id"
                 "          AND (name='scp_password'"
                 "               OR name='verinice_server_password')),"
                 "       owner, method"
                 " FROM alerts_trash WHERE method = 8 OR method = 6;");

  while (next (&alert_data))
    {
      alert_t alert;
      const char *name, *login, *password;
      user_t owner;
      credential_t new_credential;
      gchar *new_credential_id, *quoted_name, *quoted_login;
      int method;

      alert = iterator_int64 (&alert_data, 0);
      name = iterator_string (&alert_data, 1);
      login = iterator_string (&alert_data, 2);
      password = iterator_string (&alert_data, 3);
      owner = iterator_int64 (&alert_data, 4);
      method = iterator_int (&alert_data, 5);

      /* Skip the alert if it is missing login info. */
      if (name == NULL || password == NULL)
        continue;

      quoted_name = sql_quote (name);
      quoted_login = sql_quote (login);

      /* Create basic credential. */

      sql ("INSERT INTO credentials_trash"
           " (uuid, name, owner, comment, type,"
           "  creation_time, modification_time)"
           " VALUES"
           " (make_uuid (), 'Credential for Alert %s',"
           "  %llu, 'Autogenerated by migration', 'up',"
           "  m_now (), m_now ());",
           quoted_name, owner);

      new_credential = sql_last_insert_id ();
      new_credential_id = sql_string ("SELECT uuid FROM credentials_trash"
                                      " WHERE id = %llu;",
                                      new_credential);

      /* Add credential data. */
      sql ("INSERT INTO credentials_trash_data (credential, type, value)"
           " VALUES (%llu, 'username', '%s');",
           new_credential, quoted_login);

      if (disable_encrypted_credentials)
        {
          gchar *quoted_password;
          quoted_password = sql_quote (password);
          sql ("INSERT INTO credentials_trash_data (credential, type, value)"
               " VALUES (%llu, 'password', '%s');",
               new_credential, quoted_password);
          g_free (quoted_password);
        }
      else
        {
          char *secret;
          gchar *quoted_secret;

          if (!alert_data.crypt_ctx)
            alert_data.crypt_ctx = lsc_crypt_new ();

          secret = lsc_crypt_encrypt (alert_data.crypt_ctx,
                                      "password", password, NULL);
          if (!secret)
            {
              g_free (quoted_name);
              g_free (quoted_login);
              cleanup_iterator (&alert_data);
              sql_rollback ();
              return -1;
            }
          quoted_secret = sql_quote (secret);
          sql ("INSERT INTO credentials_trash_data (credential, type, value)"
               " VALUES (%llu, 'secret', '%s');",
               new_credential, quoted_secret);
          g_free (quoted_secret);
        }

      /* Update alert_method_data. */
      sql ("INSERT INTO alert_method_data_trash (alert, name, data)"
           " VALUES (%llu, '%s_credential', '%s');",
           alert,
           method == 8 ? "scp" : "verinice_server",
           new_credential_id);

      sql ("INSERT INTO alert_method_data_trash (alert, name, data)"
           " VALUES (%llu, '%s_credential_location', %d);",
           alert,
           method == 8 ? "scp" : "verinice_server",
           LOCATION_TRASH);

      /* Create permissions. */
      sql ("INSERT INTO"
           " permissions (uuid, owner, name,"
           "              comment, resource_type, resource,"
           "              resource_uuid,"
           "              resource_location, subject_type, subject,"
           "              subject_location,"
           "              creation_time, modification_time)"
           " SELECT make_uuid(), owner, 'get_credentials',"
           "         'Autogenerated by Alert migration', 'credential', %llu,"
           "         (SELECT uuid FROM credentials_trash WHERE id=%llu),"
           "         " G_STRINGIFY (LOCATION_TRASH) ", subject_type, subject,"
           "         subject_location,"
           "         m_now (), m_now ()"
           " FROM permissions"
           " WHERE resource = %llu"
           "   AND resource_type = 'alert'"
           "   AND resource_location = " G_STRINGIFY (LOCATION_TRASH)
           " GROUP BY owner, subject_type, subject, subject_location;",
           new_credential, new_credential, alert);

      sql ("INSERT INTO"
           " permissions_trash (uuid, owner, name,"
           "                    comment, resource_type, resource,"
           "                    resource_uuid,"
           "                    resource_location, subject_type, subject,"
           "                    subject_location,"
           "                    creation_time, modification_time)"
           " SELECT make_uuid(), owner, 'get_credentials',"
           "         'Autogenerated by Alert migration', 'credential', %llu,"
           "         (SELECT uuid FROM credentials_trash WHERE id=%llu),"
           "         " G_STRINGIFY (LOCATION_TRASH) ", subject_type, subject,"
           "         subject_location,"
           "         m_now (), m_now ()"
           " FROM permissions_trash"
           " WHERE resource = %llu"
           "   AND resource_type = 'alert'"
           "   AND resource_location = " G_STRINGIFY (LOCATION_TRASH)
           " GROUP BY owner, subject_type, subject, subject_location;",
           new_credential, new_credential, alert);

      g_free (new_credential_id);
      g_free (quoted_name);
      g_free (quoted_login);
    }
  cleanup_iterator (&alert_data);

  /* Remove now obsolete rows from alert_method_data and ..._trash. */
  sql ("DELETE FROM alert_method_data"
       " WHERE name='scp_username'"
       "   OR name='verinice_server_username'"
       "   OR name='scp_password'"
       "   OR name='verinice_server_password';");

  sql ("DELETE FROM alert_method_data_trash"
       " WHERE name='scp_username'"
       "   OR name='verinice_server_username'"
       "   OR name='scp_password'"
       "   OR name='verinice_server_password';");

  /* Set the database version to 166. */

  set_db_version (166);

  sql_commit ();

  return 0;
}

/**
 * @brief Mark a report format predefined.
 *
 * @param[in]  uuid  UUID of report format.
 */
static void
insert_predefined (const gchar *uuid)
{
  if (sql_int ("SELECT EXISTS (SELECT * FROM report_formats"
               "               WHERE uuid = '%s');",
               uuid))
    sql ("INSERT INTO resources_predefined (resource_type, resource)"
         " VALUES ('report_format',"
         "         (SELECT id FROM report_formats WHERE uuid = '%s'));",
         uuid);
}

/**
 * @brief Migrate the database from version 166 to version 167.
 *
 * @return 0 success, -1 error.
 */
int
migrate_166_to_167 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 166. */

  if (manage_db_version () != 166)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Ensure the tables exist for the migrator. */

  if (sql_is_sqlite3 ())
    sql ("CREATE TABLE IF NOT EXISTS resources_predefined"
         " (id INTEGER PRIMARY KEY, resource_type, resource INTEGER)");
  else
    sql ("CREATE TABLE IF NOT EXISTS resources_predefined"
         " (id SERIAL PRIMARY KEY, resource_type text, resource INTEGER)");

  /* Mark predefined report formats. */

  insert_predefined ("5057e5cc-b825-11e4-9d0e-28d24461215b");
  insert_predefined ("910200ca-dc05-11e1-954f-406186ea4fc5");
  insert_predefined ("5ceff8ba-1f62-11e1-ab9f-406186ea4fc5");
  insert_predefined ("c1645568-627a-11e3-a660-406186ea4fc5");
  insert_predefined ("9087b18c-626c-11e3-8892-406186ea4fc5");
  insert_predefined ("6c248850-1f62-11e1-b082-406186ea4fc5");
  insert_predefined ("77bd6c4a-1f62-11e1-abf0-406186ea4fc5");
  insert_predefined ("a684c02c-b531-11e1-bdc2-406186ea4fc5");
  insert_predefined ("9ca6fe72-1f62-11e1-9e7c-406186ea4fc5");
  insert_predefined ("c402cc3e-b531-11e1-9163-406186ea4fc5");
  insert_predefined ("a3810a62-1f62-11e1-9219-406186ea4fc5");
  insert_predefined ("a994b278-1f62-11e1-96ac-406186ea4fc5");
  insert_predefined ("9e5e5deb-879e-4ecc-8be6-a71cd0875cdd");
  insert_predefined ("c15ad349-bd8d-457a-880a-c7056532ee15");
  insert_predefined ("50c9950a-f326-11e4-800c-28d24461215b");

  /* Set the database version to 167. */

  set_db_version (167);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 167 to version 168.
 *
 * @return 0 success, -1 error.
 */
int
migrate_167_to_168 ()
{
  const char *uuid;

  sql_begin_immediate ();

  /* Ensure that the database is currently version 167. */

  if (manage_db_version () != 167)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The example task was removed. */

  uuid = "343435d6-91b0-11de-9478-ffd71f4c6f29";

  sql ("DELETE FROM report_counts"
       " WHERE report IN (SELECT id FROM reports"
       "                  WHERE task = (SELECT id FROM tasks"
       "                                WHERE uuid = '%s'));",
       uuid);

  sql ("DELETE FROM report_hosts"
       " WHERE report IN (SELECT id FROM reports"
       "                  WHERE task = (SELECT id FROM tasks"
       "                                WHERE uuid = '%s'));",
       uuid);

  sql ("DELETE FROM results"
       " WHERE task = (SELECT id FROM tasks"
       "               WHERE uuid = '%s');",
       uuid);

  sql ("DELETE FROM reports"
       " WHERE task = (SELECT id FROM tasks"
       "               WHERE uuid = '%s');",
       uuid);

  sql ("DELETE FROM task_preferences"
       " WHERE task = (SELECT id FROM tasks"
       "               WHERE uuid = '%s');",
       uuid);

  sql ("DELETE FROM tasks WHERE uuid = '%s';",
       uuid);

  /* Set the database version to 168. */

  set_db_version (168);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 168 to version 169.
 *
 * @param[in]  owner  Target owner.
 * @param[in]  uuid   Target UUID.
 * @param[out] new    New target.
 *
 * @return 0 success, -1 error.
 */
static void
migrate_168_to_169_copy_target (user_t owner, const gchar *uuid, target_t *new)
{
  assert (new);

  sql ("INSERT INTO targets"
       " (uuid, owner, name, comment, creation_time, modification_time,"
       "  hosts, exclude_hosts, port_list, reverse_lookup_only,"
       "  reverse_lookup_unify)"
       " SELECT make_uuid (), %llu, name, comment, m_now (), m_now (),"
       "        hosts, exclude_hosts, port_list, reverse_lookup_only,"
       "        reverse_lookup_unify"
       " FROM targets"
       " WHERE uuid = '%s';",
       owner,
       uuid);

  *new = sql_last_insert_id ();

  sql ("INSERT INTO tags"
       " (uuid, owner, name, comment, creation_time, modification_time,"
       "  resource_type, resource, resource_uuid, resource_location,"
       "  active, value)"
       " SELECT make_uuid (), %llu, name, comment, m_now (), m_now (),"
       "        resource_type, %llu,"
       "        (SELECT uuid FROM targets WHERE id = %llu),"
       "        resource_location, active, value"
       " FROM tags WHERE resource_type = 'target'"
       "           AND resource = (SELECT id FROM targets WHERE uuid = '%s')"
       "           AND resource_location = " G_STRINGIFY (LOCATION_TABLE) ";",
       owner,
       *new,
       *new,
       uuid);
}

/**
 * @brief Migrate the database from version 168 to version 169.
 *
 * @return 0 success, -1 error.
 */
int
migrate_168_to_169 ()
{
  const char *uuid;
  iterator_t users;

  sql_begin_immediate ();

  /* Ensure that the database is currently version 168. */

  if (manage_db_version () != 168)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The predefined target Localhost was removed. */

  uuid = "b493b7a8-7489-11df-a3ec-002264764cea";

  init_iterator (&users, "SELECT id FROM users;");
  while (next (&users))
    {
      user_t owner;

      owner = iterator_int64 (&users, 0);

      if (sql_int ("SELECT count (*) FROM tasks"
                   " WHERE owner = %llu"
                   " AND target = (SELECT id FROM targets"
                   "               WHERE uuid = '%s');",
                   owner,
                   uuid))
        {
          target_t new;

          /* This user is using Localhost.  Create a copy owned by the user. */

          current_credentials.username = sql_string ("SELECT name FROM users"
                                                     " WHERE owner = %llu;",
                                                     owner);
          current_credentials.uuid = sql_string ("SELECT uuid FROM users"
                                                 " WHERE owner = %llu;",
                                                 owner);

          migrate_168_to_169_copy_target (owner, uuid, &new);

          free (current_credentials.username);
          free (current_credentials.uuid);

          /* Assign the copy to the user's tasks. */

          sql ("UPDATE tasks SET target = %llu"
               " WHERE owner = %llu"
               " AND target = (SELECT id FROM targets WHERE uuid = '%s');",
               new,
               owner,
               uuid);
        }
    }
  cleanup_iterator (&users);

  /* Delete the old Localhost. */

  sql ("DELETE FROM targets WHERE uuid = '%s';",
       uuid);

  /* Set the database version to 169. */

  set_db_version (169);

  sql_commit ();

  return 0;
}

/**
 * @brief Add permission to role.
 *
 * Caller must ensure args are SQL escaped.
 *
 * @param[in]  role        Role.
 * @param[in]  permission  Permission.
 */
static void
migrate_169_to_170_add_permission (const gchar *role, const gchar *permission)
{
  sql ("INSERT INTO permissions"
       " (uuid, owner, name, comment, resource_type, resource, resource_uuid,"
       "  resource_location, subject_type, subject, subject_location,"
       "  creation_time, modification_time)"
       " VALUES"
       " (make_uuid (), NULL, lower ('%s'), '', '',"
       "  0, '', " G_STRINGIFY (LOCATION_TABLE) ", 'role',"
       "  (SELECT id FROM roles WHERE uuid = '%s'),"
       "  " G_STRINGIFY (LOCATION_TABLE) ", m_now (), m_now ());",
       permission,
       role);
}

/**
 * @brief Migrate the database from version 169 to version 170.
 *
 * @return 0 success, -1 error.
 */
int
migrate_169_to_170 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 169. */

  if (manage_db_version () != 169)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Role "User" got more DESCRIBE permissions. */

  migrate_169_to_170_add_permission ("8d453140-b74d-11e2-b0be-406186ea4fc5",
                                     "DESCRIBE_CERT");
  migrate_169_to_170_add_permission ("8d453140-b74d-11e2-b0be-406186ea4fc5",
                                     "DESCRIBE_FEED");
  migrate_169_to_170_add_permission ("8d453140-b74d-11e2-b0be-406186ea4fc5",
                                     "DESCRIBE_SCAP");

  /* Set the database version to 170. */

  set_db_version (170);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 170 to version 171.
 *
 * @return 0 success, -1 error.
 */
int
migrate_170_to_171 ()
{
  gchar *old_dir, *new_dir;
  struct stat state;

  sql_begin_immediate ();

  /* Ensure that the database is currently version 170. */

  if (manage_db_version () != 170)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The report formats trash moved to an FHS compliant location. */

  new_dir = g_build_filename (GVMD_STATE_DIR,
                              NULL);

  if (g_mkdir_with_parents (new_dir, 0755 /* "rwxr-xr-x" */))
    {
      g_warning ("%s: failed to create dir %s", __FUNCTION__, new_dir);
      g_free (new_dir);
      sql_rollback ();
      return -1;
    }

  old_dir = g_build_filename (GVMD_DATA_DIR,
                              "report_formats_trash",
                              NULL);

  if (g_lstat (old_dir, &state))
    {
      /* The old dir is missing.  Assume there are no trash report formats.
       * This helps when the database has been restored without the trash
       * directory. */

      if (errno != ENOENT)
        g_warning ("%s: g_lstat (%s) failed: %s",
                   __FUNCTION__, old_dir, g_strerror (errno));
      else
        g_warning ("%s: trash report formats directory missing (%s)",
                   __FUNCTION__, old_dir);
      g_warning ("%s: any trash report formats will be removed on startup",
                 __FUNCTION__);
    }
  else
    {
      gchar **cmd;
      gchar *standard_out = NULL;
      gchar *standard_err = NULL;
      gint exit_status;

      /* Move the directory. */

      g_mkdir_with_parents (old_dir, 0755 /* "rwxr-xr-x" */);

      cmd = (gchar **) g_malloc (4 * sizeof (gchar *));
      cmd[0] = g_strdup ("mv");
      cmd[1] = old_dir;
      cmd[2] = new_dir;
      cmd[3] = NULL;
      g_debug ("%s: Spawning in .: %s %s %s",
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
          g_debug ("%s: stdout: %s", __FUNCTION__, standard_out);
          g_debug ("%s: stderr: %s", __FUNCTION__, standard_err);
          g_free (old_dir);
          g_free (new_dir);
          g_free (cmd[0]);
          g_free (cmd);
          sql_rollback ();
          return -1;
        }

      g_free (cmd[0]);
      g_free (cmd);
    }

  g_free (old_dir);
  g_free (new_dir);

  /* Set the database version to 171. */

  set_db_version (171);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 171 to version 172.
 *
 * @return 0 success, -1 error.
 */
int
migrate_171_to_172 ()
{
  GError *error;
  gchar *old_dir_path, *new_dir_path;
  const gchar *subdir_name;
  struct stat state;

  sql_begin_immediate ();

  /* Ensure that the database is currently version 171. */

  if (manage_db_version () != 171)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The global report formats moved to an FHS compliant location. */

  new_dir_path = g_build_filename (GVMD_STATE_DIR,
                                   NULL);

  if (g_mkdir_with_parents (new_dir_path, 0755 /* "rwxr-xr-x" */))
    {
      g_warning ("%s: failed to create dir %s", __FUNCTION__, new_dir_path);
      g_free (new_dir_path);
      sql_rollback ();
      return -1;
    }

  old_dir_path = g_build_filename (GVMD_DATA_DIR,
                                   "global_report_formats",
                                   NULL);

  if (g_lstat (old_dir_path, &state))
    {
      /* The old dir is missing.  Probably we are on a fresh install with an
       * old db, so skip the moves.  There are no report formats files around
       * to move anyway, and the Manager install should have put the actual
       * files in the right place. */
      if (errno != ENOENT)
        g_warning ("%s: g_lstat (%s) failed: %s",
                   __FUNCTION__, old_dir_path, g_strerror (errno));
      else
        g_info ("%s: old global report formats directory missing (%s)",
                __FUNCTION__, old_dir_path);
    }
  else
    {
      GDir *old_dir;
      int move_failed;

      /* Iterate over subdirectories of old dir */

      error = NULL;
      old_dir = g_dir_open (old_dir_path, 0, &error);
      if (old_dir == NULL)
        {
          g_warning ("%s: Failed to open directory '%s': %s",
                     __FUNCTION__, old_dir_path, error->message);
          g_error_free (error);
          g_free (old_dir_path);
          g_free (new_dir_path);
          sql_rollback ();
          return -1;
        }

      subdir_name = g_dir_read_name (old_dir);
      move_failed = 0;
      while (subdir_name && move_failed == 0)
        {
          gchar *old_subdir_path, *new_subdir_path;
          GDir *new_subdir;

          error = NULL;
          old_subdir_path = g_build_filename (old_dir_path, subdir_name, NULL);
          new_subdir_path = g_build_filename (new_dir_path, subdir_name, NULL);
          new_subdir = g_dir_open (new_subdir_path, 0, &error);
          if (new_subdir)
            {
              g_debug ("%s: Skipping '%s', directory already exists",
                         __FUNCTION__, new_subdir_path);
              gvm_file_remove_recurse (old_subdir_path);
              g_dir_close (new_subdir);
            }
          else if (error->code == G_FILE_ERROR_NOENT)
            {
              gchar **cmd;
              gchar *standard_out = NULL;
              gchar *standard_err = NULL;
              gint exit_status;

              cmd = (gchar **) g_malloc (4 * sizeof (gchar *));
              cmd[0] = g_strdup ("mv");
              cmd[1] = old_subdir_path;
              cmd[2] = new_subdir_path;
              cmd[3] = NULL;
              g_debug ("%s: Spawning in .: %s %s %s",
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
                  g_debug ("%s: stdout: %s", __FUNCTION__, standard_out);
                  g_debug ("%s: stderr: %s", __FUNCTION__, standard_err);
                  move_failed = 1;
                }
              g_free (cmd[0]);
              g_free (cmd);
            }
          else
            {
              g_warning ("%s: failed to check directory '%s' : %s",
                         __FUNCTION__, new_subdir_path, error->message);
              move_failed = 1;
            }
          g_free (old_subdir_path);
          g_free (new_subdir_path);
          if (error)
            g_error_free (error);
          subdir_name = g_dir_read_name (old_dir);
        }

      g_dir_close (old_dir);

      if (move_failed)
        {
          sql_rollback ();
          return -1;
        }
    }
  g_free (old_dir_path);
  g_free (new_dir_path);

  /* Set the database version to 172. */

  set_db_version (172);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 172 to version 173.
 *
 * @return 0 success, -1 error.
 */
int
migrate_172_to_173 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 172. */

  if (manage_db_version () != 172)
    {
      sql_rollback ();
      return -1;
    }

  /* Remove unused columns. */
  if (sql_is_sqlite3 ())
    {
      sql ("ALTER TABLE nvts RENAME TO nvts_172;");

      sql ("CREATE TABLE IF NOT EXISTS nvts"
           " (id INTEGER PRIMARY KEY, uuid, oid, version, name, comment,"
           "  copyright, cve, bid, xref, tag, category INTEGER, family, cvss_base,"
           "  creation_time, modification_time, solution_type TEXT, qod INTEGER,"
           "  qod_type TEXT);");

      sql ("INSERT INTO nvts"
           " (id, uuid, oid, version, name, comment, copyright, cve,"
           "  bid, xref, tag, category, family, cvss_base, creation_time,"
           "  modification_time, solution_type, qod, qod_type)"
           " SELECT id, uuid, oid, version, name, comment, copyright, cve,"
           "  bid, xref, tag, category, family, cvss_base, creation_time,"
           "  modification_time, solution_type, qod, qod_type"
           " FROM nvts_172;");

      sql ("DROP TABLE nvts_172;");
    }
  else
    sql ("ALTER TABLE nvts DROP COLUMN summary;");

  /* Set the database version to 173. */

  set_db_version (173);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 173 to version 174.
 *
 * @return 0 success, -1 error.
 */
int
migrate_173_to_174 ()
{
  sql_begin_immediate ();
  report_format_t report_format;

  /* Ensure that the database is currently version 173. */

  if (manage_db_version () != 173)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Get row id of Verinice ISM report format */
  sql_int64 (&report_format,
             "SELECT id FROM report_formats"
             " WHERE uuid='c15ad349-bd8d-457a-880a-c7056532ee15';");

  // Update version number in summary and description
  sql ("UPDATE report_formats"
       " SET summary='Greenbone Verinice ISM Report, v3.0.0.',"
       "     description='Information Security Management Report for Verinice import, version 3.0.0.\n'"
       " WHERE id = %llu",
       report_format);

  // Remove old attach params
  sql ("DELETE FROM report_format_params"
       " WHERE report_format = %llu"
       "   AND name LIKE 'Attach %%%% report'",
       report_format);

  // Add new attach param
  sql ("INSERT INTO report_format_params (report_format, name, type, value,"
       " type_min, type_max, type_regex, fallback)"
       " VALUES (%lli, 'Attached report formats', %i, '%s', 0, 0, '', 1);",
       report_format,
       REPORT_FORMAT_PARAM_TYPE_REPORT_FORMAT_LIST,
       "6c248850-1f62-11e1-b082-406186ea4fc5");

  /* Set the database version to 174. */

  set_db_version (174);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 174 to version 175.
 *
 * @return 0 success, -1 error.
 */
int
migrate_174_to_175 ()
{
  GError *error;
  int move_failed;
  gchar *old_dir_path, *new_dir_path;
  const gchar *subdir_name;
  GDir *old_dir;

  sql_begin_immediate ();

  /* Ensure that the database is currently version 174. */

  if (manage_db_version () != 174)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The global report formats moved back to the DATA directory, because
   * they are being merged into the predefined report formats. */

  new_dir_path = g_build_filename (GVMD_DATA_DIR,
                                   "report_formats",
                                   NULL);

  /* The new dir should exist already, so this will work even if we don't
   * have write permission in GVMD_DATA_DIR. */
  if (g_mkdir_with_parents (new_dir_path, 0755 /* "rwxr-xr-x" */))
    {
      g_warning ("%s: failed to create dir %s", __FUNCTION__, new_dir_path);
      g_free (new_dir_path);
      sql_rollback ();
      return -1;
    }

  old_dir_path = g_build_filename (GVMD_STATE_DIR,
                                   "global_report_formats",
                                   NULL);

  /* Ensure the old dir exists. */

  g_mkdir_with_parents (old_dir_path, 0755 /* "rwxr-xr-x" */);

  /* Iterate over subdirectories of old dir. */

  error = NULL;
  old_dir = g_dir_open (old_dir_path, 0, &error);
  if (old_dir == NULL)
    {
      g_warning ("%s: Failed to open directory '%s': %s",
                 __FUNCTION__, old_dir_path, error->message);
      g_error_free (error);
      g_free (old_dir_path);
      g_free (new_dir_path);
      sql_rollback ();
      return -1;
    }

  subdir_name = g_dir_read_name (old_dir);
  move_failed = 0;
  while (subdir_name && move_failed == 0)
    {
      gchar *old_subdir_path, *new_subdir_path;
      GDir *new_subdir;

      error = NULL;
      old_subdir_path = g_build_filename (old_dir_path, subdir_name, NULL);
      new_subdir_path = g_build_filename (new_dir_path, subdir_name, NULL);
      new_subdir = g_dir_open (new_subdir_path, 0, &error);
      if (new_subdir)
        {
          g_debug ("%s: Skipping '%s', directory already exists",
                   __FUNCTION__, new_subdir_path);
          gvm_file_remove_recurse (old_subdir_path);
          g_dir_close (new_subdir);
        }
      else if (error->code == G_FILE_ERROR_NOENT)
        {
          gchar **cmd;
          gchar *standard_out = NULL;
          gchar *standard_err = NULL;
          gint exit_status;

          cmd = (gchar **) g_malloc (4 * sizeof (gchar *));
          cmd[0] = g_strdup ("mv");
          cmd[1] = old_subdir_path;
          cmd[2] = new_subdir_path;
          cmd[3] = NULL;
          g_debug ("%s: Spawning in .: %s %s %s",
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
              g_debug ("%s: stdout: %s", __FUNCTION__, standard_out);
              g_debug ("%s: stderr: %s", __FUNCTION__, standard_err);
              move_failed = 1;
            }
          g_free (cmd[0]);
          g_free (cmd);
        }
      else
        {
          g_warning ("%s: failed to check directory '%s' : %s",
                     __FUNCTION__, new_subdir_path, error->message);
          move_failed = 1;
        }
      g_free (old_subdir_path);
      g_free (new_subdir_path);
      if (error)
        g_error_free (error);
      subdir_name = g_dir_read_name (old_dir);
    }
  g_free (new_dir_path);
  g_dir_close (old_dir);

  if (move_failed)
    {
      g_free (old_dir_path);
      sql_rollback ();
      return -1;
    }

  gvm_file_remove_recurse (old_dir_path);
  g_free (old_dir_path);

  /* Set the database version to 175. */

  set_db_version (175);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 175 to version 176.
 *
 * @return 0 success, -1 error.
 */
int
migrate_175_to_176 ()
{

  sql_begin_immediate ();

  /* Ensure that the database is currently version 175. */

  if (manage_db_version () != 175)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Change the default scanner to use unix file sockets. */
  sql ("UPDATE scanners SET host = '" GVM_RUN_DIR "/openvassd.sock'"
       " WHERE uuid = '" SCANNER_UUID_DEFAULT "';");

  /* Set the database version to 176. */

  set_db_version (176);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 176 to version 177.
 *
 * @return 0 success, -1 error.
 */
int
migrate_176_to_177 ()
{
  int now;

  sql_begin_immediate ();

  /* Ensure that the database is currently version 176. */

  if (manage_db_version () != 176)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The feed DESCRIBE commands were merged to new command GET_FEEDS. */

  now = time (NULL);

  sql ("INSERT INTO permissions"
       " (uuid, owner, name, comment, resource_type, resource, resource_uuid,"
       "  resource_location, subject_type, subject, subject_location,"
       "  creation_time, modification_time)"
       " SELECT make_uuid (), *, %i, %i"
       " FROM (SELECT DISTINCT owner, 'get_feeds', comment, resource_type,"
       "              resource, resource_uuid, resource_location,"
       "              subject_type, subject, subject_location"
       "       FROM permissions"
       "       WHERE (name = 'describe_feed'"
       "              OR name = 'describe_scap'"
       "              OR name = 'describe_cert'))"
       "      AS subquery;",
       now,
       now);

  sql ("DELETE FROM permissions"
       " WHERE (name = 'describe_feed'"
       "        OR name = 'describe_scap'"
       "        OR name = 'describe_cert');");

  /* Set the database version to 177. */

  set_db_version (177);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 177 to version 178.
 *
 * @return 0 success, -1 error.
 */
int
migrate_177_to_178 ()
{
  credential_t credential;
  sql_begin_immediate ();

  /* Ensure that the database is currently version 177. */

  if (manage_db_version () != 177)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Remove CA certificate from default scanner. */
  sql ("UPDATE scanners SET ca_pub = NULL"
       " WHERE uuid = '" SCANNER_UUID_DEFAULT "';");

  /* Get credential to delete it if possible */
  sql_int64 (&credential,
             "SELECT credential FROM scanners"
             " WHERE uuid = '" SCANNER_UUID_DEFAULT "'");

  /* Remove reference to credential from default scanner. */
  sql ("UPDATE scanners SET credential = NULL"
       " WHERE uuid = '" SCANNER_UUID_DEFAULT "';");

  /* Delete credential of default scanner if it is not used elsewhere. */
  if ((sql_int ("SELECT count(*) FROM scanners"
                " WHERE credential = %llu"
                "   AND uuid != '" SCANNER_UUID_DEFAULT "';",
                credential) == 0)
      && (sql_int ("SELECT count(*) FROM scanners_trash"
                   " WHERE credential = %llu"
                   "   AND credential_location = %d;",
                   credential, LOCATION_TABLE) == 0)
      && (sql_int ("SELECT count(*) FROM targets_login_data"
                   " WHERE credential = %llu;",
                   credential) == 0)
      && (sql_int ("SELECT count(*) FROM targets_trash_login_data"
                   " WHERE credential = %llu"
                   "   AND credential_location = %d;",
                   credential, LOCATION_TABLE) == 0)
      && (sql_int ("SELECT count(*) FROM slaves"
                   " WHERE credential = %llu;",
                   credential) == 0)
      && (sql_int ("SELECT count(*) FROM slaves_trash"
                   " WHERE credential = %llu"
                   "   AND credential_location = %d;",
                   credential, LOCATION_TABLE) == 0))
    {
      sql ("DELETE FROM credentials_data WHERE credential = %llu",
           credential);
      sql ("DELETE FROM credentials WHERE id = %llu",
           credential);
    }

  /* Set the database version to 178. */

  set_db_version (178);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 178 to version 179.
 *
 * @return 0 success, -1 error.
 */
int
migrate_178_to_179 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 178. */

  if (manage_db_version () != 178)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Reports got new columns for slave username and password. */

  sql ("ALTER TABLE reports ADD COLUMN slave_username TEXT;");
  sql ("ALTER TABLE reports ADD COLUMN slave_password TEXT;");

  sql ("UPDATE reports"
       " SET slave_username = (SELECT credentials_data.value"
       "                       FROM slaves, credentials_data"
       "                       WHERE slaves.id = (SELECT id FROM slaves"
       "                                          WHERE uuid = slave_uuid)"
       "                       AND credentials_data.credential"
       "                           = slaves.credential"
       "                       AND credentials_data.type = 'username');");

  sql ("UPDATE reports"
       " SET slave_password = (SELECT credentials_data.value"
       "                       FROM slaves, credentials_data"
       "                       WHERE slaves.id = (SELECT id FROM slaves"
       "                                          WHERE uuid = slave_uuid)"
       "                       AND credentials_data.credential"
       "                           = slaves.credential"
       "                       AND credentials_data.type = 'username');");

  /* Set the database version to 179. */

  set_db_version (179);

  sql_commit ();

  return 0;
}

/**
 * @brief Update a reference for migrate_179_to_180.
 *
 * @param[in]  table  Table.
 * @param[in]  trash  Whether to update from scanners_trash.
 *
 * @return 0 success, -1 error.
 */
void
migrate_179_to_180_update_ref (const gchar *table, int trash)
{
  sql ("UPDATE %s"
       " SET resource_type = 'scanner',"
       "     resource = (SELECT id FROM scanners%s"
       "                 WHERE uuid = resource_uuid)"
       " WHERE resource_type = 'slave'"
       " AND resource_location = %i;",
       table,
       trash ? "_trash" : "",
       trash ? LOCATION_TRASH : LOCATION_TABLE);
}

/**
 * @brief Migrate the database from version 179 to version 180.
 *
 * @return 0 success, -1 error.
 */
int
migrate_179_to_180 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 179. */

  if (manage_db_version () != 179)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Slaves were replaced by GMP scanners. */

  sql ("DELETE FROM settings"
       " WHERE uuid = 'aec201fa-8a82-4b61-bebe-a44ea93b2909'"
       "       OR uuid = '2681c32a-8dfd-40c9-a9c6-8d4e2c7799eb';");

  sql ("UPDATE filters"
       " SET type = replace (type, 'slave', 'scanner');");

  sql ("UPDATE filters_trash"
       " SET type = replace (type, 'slave', 'scanner');");

  sql ("INSERT INTO scanners (uuid, owner, name, comment, host, port,"
       "                      creation_time, modification_time, credential,"
       "                      type, ca_pub)"
       " SELECT uuid, owner, name, comment, host, CAST (port AS INTEGER),"
       "        creation_time, modification_time, credential, %i, NULL"
       " FROM slaves;",
       SCANNER_TYPE_GMP);

  migrate_179_to_180_update_ref ("tags", 0);
  migrate_179_to_180_update_ref ("tags_trash", 0);
  migrate_179_to_180_update_ref ("permissions", 0);
  migrate_179_to_180_update_ref ("permissions_trash", 0);

  sql ("UPDATE tasks"
       " SET scanner = (SELECT id FROM scanners"
       "                WHERE uuid = (SELECT uuid FROM slaves"
       "                              WHERE id = tasks.slave)),"
       "     slave = 0"
       " WHERE slave != 0"
       " AND slave_location = " G_STRINGIFY (LOCATION_TABLE) ";");

  sql ("INSERT INTO scanners_trash (uuid, owner, name, comment, host, port,"
       "                            creation_time, modification_time,"
       "                            credential, type, ca_pub)"
       " SELECT uuid, owner, name, comment, host, CAST (port AS INTEGER),"
       "        creation_time, modification_time, credential, %i, NULL"
       " FROM slaves_trash;",
       SCANNER_TYPE_GMP);

  migrate_179_to_180_update_ref ("tags", 1);
  migrate_179_to_180_update_ref ("tags_trash", 1);
  migrate_179_to_180_update_ref ("permissions", 1);
  migrate_179_to_180_update_ref ("permissions_trash", 1);

  sql ("UPDATE permissions"
       " SET name = replace (name, 'slave', 'scanner');");

  sql ("UPDATE permissions_trash"
       " SET name = replace (name, 'slave', 'scanner');");

  sql ("UPDATE tasks"
       " SET scanner = (SELECT id FROM scanners_trash"
       "                WHERE uuid = (SELECT uuid FROM slaves_trash"
       "                              WHERE id = tasks.slave)),"
       "     slave = 0"
       " WHERE slave != 0"
       " AND slave_location = " G_STRINGIFY (LOCATION_TRASH) ";");

  sql ("DROP TABLE slaves;");
  sql ("DROP TABLE slaves_trash;");

  /* Set the database version to 180. */

  set_db_version (180);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 180 to version 181.
 *
 * @return 0 success, -1 error.
 */
int
migrate_180_to_181 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 180. */

  if (manage_db_version () != 180)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Unused column "time" was removed from table tasks.
   *
   * Remove slave columns from task at the same time. */

  if (sql_is_sqlite3 ())
    {
      sql ("ALTER TABLE tasks RENAME TO tasks_180;");

      sql ("CREATE TABLE IF NOT EXISTS tasks"
           " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, hidden INTEGER,"
           "  comment, run_status INTEGER, start_time, end_time,"
           "  config INTEGER, target INTEGER, schedule INTEGER, schedule_next_time,"
           "  schedule_periods INTEGER, config_location INTEGER,"
           "  target_location INTEGER, schedule_location INTEGER,"
           "  scanner_location INTEGER, upload_result_count INTEGER,"
           "  hosts_ordering, scanner, alterable, creation_time,"
           "  modification_time);");

      sql ("INSERT INTO tasks"
           " (id, uuid, owner, name, hidden, comment, run_status, start_time,"
           "  end_time, config, target, schedule, schedule_next_time,"
           "  schedule_periods, config_location, target_location,"
           "  schedule_location, scanner_location, upload_result_count,"
           "  hosts_ordering, scanner, alterable, creation_time,"
           "  modification_time)"
           " SELECT id, uuid, owner, name, hidden, comment, run_status,"
           "        start_time, end_time, config, target, schedule,"
           "        schedule_next_time, schedule_periods, config_location,"
           "        target_location, schedule_location, scanner_location,"
           "        upload_result_count, hosts_ordering, scanner, alterable,"
           "        creation_time, modification_time"
           " FROM tasks_180;");

      sql ("DROP TABLE tasks_180;");
    }
  else
    {
      sql ("ALTER TABLE tasks DROP COLUMN slave;");
      sql ("ALTER TABLE tasks DROP COLUMN slave_location;");
    }

  /* Set the database version to 181. */

  set_db_version (181);

  sql_commit ();

  return 0;
}

/**
 * @brief Move signatures.
 *
 * @param[in]  dest  Destination directory basename.
 *
 * @return 0 success, -1 error.
 */
int
migrate_181_to_182_move (const char *dest)
{
  gchar *new_dir_path, *old_dir_path;
  GError *error;
  GDir *old_dir;
  const gchar *asc_name;
  int move_failed;

  new_dir_path = g_build_filename (GVMD_STATE_DIR,
                                   "signatures",
                                   dest,
                                   NULL);

  if (g_mkdir_with_parents (new_dir_path, 0755 /* "rwxr-xr-x" */))
    {
      g_warning ("%s: failed to create dir %s", __FUNCTION__, new_dir_path);
      g_free (new_dir_path);
      return -1;
    }

  old_dir_path = g_build_filename (GVM_NVT_DIR,
                                   "private",
                                   dest,
                                   NULL);

  error = NULL;
  old_dir = g_dir_open (old_dir_path, 0, &error);
  if (old_dir == NULL)
    {
      if (error->code == G_FILE_ERROR_NOENT)
        /* No directory means no signatures to copy. */
        goto free_exit;
      g_warning ("%s: Failed to open directory '%s': %s",
                 __FUNCTION__, old_dir_path, error->message);
      g_error_free (error);
      g_free (old_dir_path);
      g_free (new_dir_path);
      return -1;
    }

  asc_name = g_dir_read_name (old_dir);
  move_failed = 0;
  while (asc_name && move_failed == 0)
    {
      gchar *old_asc_path, *new_asc_path;

      gchar **cmd;
      gchar *standard_out = NULL;
      gchar *standard_err = NULL;
      gint exit_status;

      error = NULL;
      old_asc_path = g_build_filename (old_dir_path, asc_name, NULL);
      new_asc_path = g_build_filename (new_dir_path, asc_name, NULL);

      cmd = (gchar **) g_malloc (4 * sizeof (gchar *));
      cmd[0] = g_strdup ("mv");
      cmd[1] = old_asc_path;
      cmd[2] = new_asc_path;
      cmd[3] = NULL;
      g_debug ("%s: Spawning in .: %s %s %s",
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
          g_debug ("%s: stdout: %s", __FUNCTION__, standard_out);
          g_debug ("%s: stderr: %s", __FUNCTION__, standard_err);
          move_failed = 1;
        }
      g_free (cmd[0]);
      g_free (cmd);
      g_free (old_asc_path);
      g_free (new_asc_path);
      if (error)
        g_error_free (error);
      asc_name = g_dir_read_name (old_dir);
    }
  g_free (new_dir_path);
  g_dir_close (old_dir);

  if (move_failed)
    {
      g_free (old_dir_path);
      return -1;
    }

  gvm_file_remove_recurse (old_dir_path);
 free_exit:
  g_free (old_dir_path);

  return 0;
}

/**
 * @brief Migrate the database from version 181 to version 182.
 *
 * @return 0 success, -1 error.
 */
int
migrate_181_to_182 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 181. */

  if (manage_db_version () != 181)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* The directories used by users to provide report format signatures for
   * their own report formats and agents moved from
   * FEED/plugins/private/report_formats to
   * STATE/var/lib/openvas/openvasmd/report_formats. */

  if (migrate_181_to_182_move ("report_formats"))
    {
      sql_rollback ();
      return -1;
    }

  /* Set the database version to 182. */

  set_db_version (182);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 182 to version 183.
 *
 * @return 0 success, -1 error.
 */
int
migrate_182_to_183 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 182. */

  if (manage_db_version () != 182)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* Slave usernames and passwords were removed from table reports. */

  if (sql_is_sqlite3 ())
    {
      sql ("ALTER TABLE reports RENAME TO reports_182;");

      sql ("CREATE TABLE reports"
           " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, hidden INTEGER,"
           "  task INTEGER, date INTEGER, start_time, end_time, nbefile, comment,"
           "  scan_run_status INTEGER, slave_progress, slave_task_uuid,"
           "  slave_uuid, slave_name, slave_host, slave_port, source_iface,"
           "  flags INTEGER);");

      sql ("INSERT INTO reports"
           " (id, uuid, owner, hidden, task, date, start_time, end_time,"
           "  nbefile, comment, scan_run_status, slave_progress,"
           "  slave_task_uuid, slave_uuid, slave_name, slave_host,"
           "  slave_port, source_iface, flags)"
           " SELECT id, uuid, owner, hidden, task, date, start_time, end_time,"
           "        nbefile, comment, scan_run_status, slave_progress,"
           "        slave_task_uuid, slave_uuid, slave_name, slave_host,"
           "        slave_port, source_iface, flags"
           " FROM reports_182;");

      sql ("DROP TABLE reports_182;");
    }
  else
    {
      sql ("ALTER TABLE reports DROP COLUMN slave_username;");
      sql ("ALTER TABLE reports DROP COLUMN slave_password;");
    }

  /* Set the database version to 183. */

  set_db_version (183);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 183 to version 184.
 *
 * @return 0 success, -1 error.
 */
int
migrate_183_to_184 ()
{
  sql_begin_immediate ();

  /* Ensure that the database is currently version 183. */

  if (manage_db_version () != 183)
    {
      sql_rollback ();
      return -1;
    }

  /* Update the database. */

  /* GMP command GET_NVT_FEED_VERSION was removed. */

  sql ("DELETE FROM permissions WHERE name = 'get_nvt_feed_version';");

  sql ("DELETE FROM permissions_trash WHERE name = 'get_nvt_feed_version';");

  /* Deactivate report formats that are not predefined,
   *  as some older ones may cause problems.
   */
  sql ("UPDATE report_formats SET flags = (flags & ~1) WHERE id NOT IN"
       " (SELECT resource FROM resources_predefined"
       "  WHERE resource_type='report_format');");

  /* Set the database version to 184. */

  set_db_version (184);

  sql_commit ();

  return 0;
}

/**
 * @brief Migrate the database from version 184 to version 185.
 *
 * @return 0 success, -1 error.
 */
int
migrate_184_to_185 ()
{
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
  if (! sql_is_sqlite3 ())
    {
      iterator_t fkeys;
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
          const char* constraint_name;
          constraint_name = iterator_string (&fkeys, 0);
          sql ("ALTER TABLE configs_trash DROP constraint %s",
               constraint_name);
        }

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

  if (sql_is_sqlite3 ())
    sql ("CREATE TABLE IF NOT EXISTS results_188"
         " (id INTEGER PRIMARY KEY, uuid, task INTEGER, host, port, nvt,"
         "  result_nvt, type, description, report, nvt_version, severity REAL,"
         "  qod INTEGER, qod_type TEXT, owner INTEGER, date INTEGER)");
  else
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
  if (sql_is_sqlite3 ())
    sql ("DROP TABLE results;");
  else
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

      ical_component
        = icalendar_from_old_schedule_data (first_time, period, period_months,
                                            duration, byday, zone);
      quoted_ical = sql_quote (icalcomponent_as_ical_string (ical_component));

      g_debug ("%s: schedule %llu - first: %s (%s), period: %ld,"
               " period_months: %ld, duration: %ld - byday: %d\n"
               "generated iCalendar:\n%s",
               __FUNCTION__, schedule,
               iso_time_tz (&first_time, zone, NULL),
               zone, period, period_months, duration, byday,
               quoted_ical);

      sql ("UPDATE schedules SET icalendar = '%s' WHERE id = %llu",
           quoted_ical, schedule);

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

      ical_component
        = icalendar_from_old_schedule_data (first_time, period, period_months,
                                            duration, byday, zone);
      quoted_ical = sql_quote (icalcomponent_as_ical_string (ical_component));

      g_debug ("%s: trash schedule %llu - first: %s (%s), period: %ld,"
               " period_months: %ld, duration: %ld - byday: %d\n"
               "generated iCalendar:\n%s",
               __FUNCTION__, schedule,
               iso_time_tz (&first_time, zone, NULL),
               zone, period, period_months, duration, byday,
               quoted_ical);

      sql ("UPDATE schedules_trash SET icalendar = '%s' WHERE id = %llu",
           quoted_ical, schedule);

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

  if (sql_is_sqlite3 ())
    {
      sql ("CREATE TABLE IF NOT EXISTS tag_resources"
           " (tag INTEGER,"
           "  resource_type text,"
           "  resource INTEGER,"
           "  resource_uuid TEXT,"
           "  resource_location INTEGER);");

      sql ("CREATE TABLE IF NOT EXISTS tag_resources_trash"
           " (tag INTEGER,"
           "  resource_type text,"
           "  resource INTEGER,"
           "  resource_uuid TEXT,"
           "  resource_location INTEGER);");
    }
  else
    {
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
    }

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

  if (sql_is_sqlite3 ())
    {
      sql ("ALTER TABLE tags RENAME TO tags_191;");
      sql ("ALTER TABLE tags_trash RENAME TO tags_trash_191;");

      sql ("CREATE TABLE tags"
           " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
           "  creation_time, modification_time, resource_type,"
           "  active, value);");

      sql ("INSERT INTO tags"
           " (id, uuid, owner, name, comment,"
           "  creation_time, modification_time, resource_type,"
           "  active, value)"
           " SELECT id, uuid, owner, name, comment,"
           "  creation_time, modification_time, resource_type,"
           "  active, value"
           " FROM tags_191;");

      sql ("CREATE TABLE tags_trash"
           " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
           "  creation_time, modification_time, resource_type,"
           "  active, value);");

      sql ("INSERT INTO tags_trash"
           " (id, uuid, owner, name, comment,"
           "  creation_time, modification_time, resource_type,"
           "  active, value)"
           " SELECT id, uuid, owner, name, comment,"
           "  creation_time, modification_time, resource_type,"
           "  active, value"
           " FROM tags_trash_191;");

      sql ("DROP TABLE tags_191;");
      sql ("DROP TABLE tags_trash_191;");
    }
  else
    {
      sql ("ALTER TABLE tags DROP COLUMN resource;");
      sql ("ALTER TABLE tags DROP COLUMN resource_uuid;");
      sql ("ALTER TABLE tags DROP COLUMN resource_location;");

      sql ("ALTER TABLE tags_trash DROP COLUMN resource;");
      sql ("ALTER TABLE tags_trash DROP COLUMN resource_uuid;");
      sql ("ALTER TABLE tags_trash DROP COLUMN resource_location;");
    }

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

  if (sql_is_sqlite3 ())
    {
      sql ("ALTER TABLE nvts RENAME TO nvts_193;");

      sql ("CREATE TABLE IF NOT EXISTS nvts"
           " (id INTEGER PRIMARY KEY, uuid, oid, name, comment,"
           "  copyright, cve, bid, xref, tag, category INTEGER, family,"
           "  cvss_base, creation_time, modification_time, solution_type TEXT,"
           "  qod INTEGER, qod_type TEXT);");

      sql ("INSERT INTO nvts"
           " (id, uuid, oid, name, comment, copyright, cve, bid, xref, tag,"
           "  category, family, cvss_base, creation_time, modification_time,"
           "  solution_type, qod, qod_type)"
           " SELECT"
           "  id, uuid, oid, name, comment, copyright, cve, bid, xref, tag,"
           "  category, family, cvss_base, creation_time, modification_time,"
           "  solution_type, qod, qod_type"
           " FROM nvts_193;");

      sql ("DROP TABLE nvts_193;");
    }
  else
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

  if (sql_is_sqlite3 ())
    sql ("CREATE TABLE IF NOT EXISTS results_trash"
         " (id INTEGER PRIMARY KEY, uuid, task INTEGER, host, port, nvt,"
         "  result_nvt, type, description, report, nvt_version, severity REAL,"
         "  qod INTEGER, qod_type TEXT, owner INTEGER, date INTEGER,"
         "  hostname TEXT)");
  else
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

  if (sql_is_sqlite3 ())
    {
      sql ("ALTER TABLE reports RENAME TO reports_196;");

      sql ("CREATE TABLE IF NOT EXISTS reports"
           " (id INTEGER PRIMARY KEY, uuid, owner INTEGER,"
           "  task INTEGER, date INTEGER, start_time, end_time, nbefile, comment,"
           "  scan_run_status INTEGER, slave_progress, slave_task_uuid,"
           "  slave_uuid, slave_name, slave_host, slave_port, source_iface,"
           "  flags INTEGER);");

      sql ("INSERT INTO reports"
           " (id, uuid, owner, task, date, start_time, end_time, nbefile,"
           "  comment, scan_run_status, slave_progress, slave_task_uuid,"
           "  slave_uuid, slave_name, slave_host, slave_port, source_iface,"
           "  flags)"
           " SELECT"
           "  id, uuid, owner, task, date, start_time, end_time, nbefile,"
           "  comment, scan_run_status, slave_progress, slave_task_uuid,"
           "  slave_uuid, slave_name, slave_host, slave_port, source_iface,"
           "  flags"
           " FROM reports_196;");

      sql ("DROP TABLE reports_196;");
    }
  else
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

  if (sql_is_sqlite3 ())
    {
      sql ("ALTER TABLE nvts RENAME TO nvts_197;");

      sql ("CREATE TABLE IF NOT EXISTS nvts"
           " (id INTEGER PRIMARY KEY, uuid, oid, name, comment,"
           "  cve, bid, xref, tag, category INTEGER, family, cvss_base,"
           "  creation_time, modification_time, solution_type TEXT, qod INTEGER,"
           "  qod_type TEXT);");

      sql ("INSERT INTO nvts"
           " (id, uuid, oid, name, comment, cve, bid, xref, tag, category,"
           "  family, cvss_base, creation_time, modification_time,"
           "  solution_type, qod, qod_type)"
           " SELECT"
           "  id, uuid, oid, name, comment, cve, bid, xref, tag, category,"
           "  family, cvss_base, creation_time, modification_time,"
           "  solution_type, qod, qod_type"
           " FROM nvts_197;");

      sql ("DROP TABLE nvts_197;");
    }
  else
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
#define MIGRATE_TO_200_NVT_SELECTOR_UUID_DISCOVERY "0d9a2738-8fe2-4e22-8f26-bb886179e759"

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

  INSERT_PERMISSION (get_tickets, ROLE_UUID_OBSERVER);

  INSERT_PERMISSION (get_tickets, ROLE_UUID_USER);
  INSERT_PERMISSION (create_ticket, ROLE_UUID_USER);
  INSERT_PERMISSION (modify_ticket, ROLE_UUID_USER);
  INSERT_PERMISSION (delete_ticket, ROLE_UUID_USER);

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

  if (sql_is_sqlite3 ())
    {
      /* This is a lot easier that migrating.  No real user
       * should have been using the ticket implementation yet
       * so it is safe. */
      sql ("DROP TABLE IF EXISTS ticket_results;");
      sql ("DROP TABLE IF EXISTS tickets;");
      sql ("DROP TABLE IF EXISTS ticket_results_trash;");
      sql ("DROP TABLE IF EXISTS tickets_trash;");
    }
  else
    {
      sql ("ALTER TABLE tickets DROP COLUMN orphaned_time;");

      move ("tickets", "solved_comment", "fixed_comment");
      move ("tickets", "solved_time", "fixed_time");
      move ("tickets", "confirmed_report", "fix_verified_report");
      move ("tickets", "confirmed_time", "fix_verified_time");

      move ("tickets_trash", "solved_comment", "fixed_comment");
      move ("tickets_trash", "solved_time", "fixed_time");
      move ("tickets_trash", "confirmed_report", "fix_verified_report");
      move ("tickets_trash", "confirmed_time", "fix_verified_time");
    }

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

  if (sql_is_sqlite3 ())
    {
      /* This is a lot easier that migrating.  No real user
       * should have been using the ticket implementation yet
       * so it is safe. */
      sql ("DROP TABLE IF EXISTS ticket_results;");
      sql ("DROP TABLE IF EXISTS tickets;");
      sql ("DROP TABLE IF EXISTS ticket_results_trash;");
      sql ("DROP TABLE IF EXISTS tickets_trash;");
    }
  else
    {
      sql ("ALTER TABLE tickets ADD COLUMN open_comment text;");
      sql ("UPDATE tickets SET open_comment = 'No comment for migration.';");

      sql ("ALTER TABLE tickets_trash ADD COLUMN open_comment text;");
      sql ("UPDATE tickets_trash SET open_comment = 'No comment for migration.';");
    }

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

  if (sql_is_sqlite3 ())
    {
      /* This is a lot easier that migrating.  No real user
       * should have been using the ticket implementation yet
       * so it is safe. */
      sql ("DROP TABLE IF EXISTS ticket_results;");
      sql ("DROP TABLE IF EXISTS tickets;");
      sql ("DROP TABLE IF EXISTS ticket_results_trash;");
      sql ("DROP TABLE IF EXISTS tickets_trash;");
    }
  else
    {
      move ("tickets", "open_comment", "open_note");
      move ("tickets", "fixed_comment", "fixed_note");
      move ("tickets", "closed_comment", "closed_note");

      move ("tickets_trash", "open_comment", "open_note");
      move ("tickets_trash", "fixed_comment", "fixed_note");
      move ("tickets_trash", "closed_comment", "closed_note");
    }

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
      oid = sql_string ("SELECT oid FROM nvts WHERE name = '%s';",
                        quoted_nvt_name);

      // Update
      if (oid)
        {
          new_name = g_strdup_printf ("%s:%s:%s", oid, type, preference);
          quoted_new_name = sql_quote (new_name);
          sql ("UPDATE \"%s\" SET name = '%s' WHERE id = %llu",
              table_name, quoted_new_name, rowid);
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

#undef UPDATE_CHART_SETTINGS
#undef UPDATE_DASHBOARD_SETTINGS

/**
 * @brief Array of database version migrators.
 */
static migrator_t database_migrators[]
 = {{146, migrate_145_to_146}, // v6.0: rev 146
    {147, migrate_146_to_147},
    {148, migrate_147_to_148},
    {149, migrate_148_to_149},
    {150, migrate_149_to_150},
    {151, migrate_150_to_151},
    {152, migrate_151_to_152},
    {153, migrate_152_to_153},
    {154, migrate_153_to_154},
    {155, migrate_154_to_155},
    {156, migrate_155_to_156},
    {157, migrate_156_to_157},
    {158, migrate_157_to_158},
    {159, migrate_158_to_159},
    {160, migrate_159_to_160},
    {161, migrate_160_to_161},
    {162, migrate_161_to_162},
    {163, migrate_162_to_163},
    {164, migrate_163_to_164},
    {165, migrate_164_to_165},
    {166, migrate_165_to_166},
    {167, migrate_166_to_167},
    {168, migrate_167_to_168},
    {169, migrate_168_to_169},
    {170, migrate_169_to_170},
    {171, migrate_170_to_171},
    {172, migrate_171_to_172},
    {173, migrate_172_to_173},
    {174, migrate_173_to_174},
    {175, migrate_174_to_175},
    {176, migrate_175_to_176},
    {177, migrate_176_to_177},
    {178, migrate_177_to_178},
    {179, migrate_178_to_179},
    {180, migrate_179_to_180},
    {181, migrate_180_to_181},
    {182, migrate_181_to_182},
    {183, migrate_182_to_183},
    {184, migrate_183_to_184},
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
                     (GLogFunc) gvm_log_func,
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
static int
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
                     (GLogFunc) gvm_log_func,
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
